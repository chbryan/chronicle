#!/usr/bin/env python3
"""
Chronicle-LF (Live Feed)
- Continuous allowlisted RSS ingestion with conditional GET caching (ETag / If-Modified-Since)
- SQLite archival with integrity hashes + dedupe
- OPLOG per cycle: logs/YYYYMMDD_HHMM_Chronicle-LF_<BRANCH>.log
- Optional JSONL export per cycle
- Optional preview fetch (robots-aware) + coordinate-like redaction
- Optional email forwarding (SMTP) from a chosen sender to a chosen recipient

Guardrails (by design): No geocoding, no precise coordinate extraction/output, no real-time force tracking.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import email.utils
import getpass
import hashlib
import json
import os
import re
import signal
import sqlite3
import sys
import textwrap
import time
import urllib.parse
import urllib.robotparser
from dataclasses import dataclass
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import feedparser  # pip install feedparser
import requests    # pip install requests
import yaml        # pip install pyyaml
from bs4 import BeautifulSoup  # pip install beautifulsoup4


# -----------------------------
# Defaults (per repo README)
# -----------------------------
DEFAULT_CONFIG = "sources.yaml"
DEFAULT_DB = os.path.join("data", "chronicle.db")
DEFAULT_LOG_DIR = "logs"
DEFAULT_BRANCH = "USMC"
DEFAULT_TZ = "America/Chicago"

# Per user request:
DEFAULT_KEYWORD = "Iran"
DEFAULT_INTERVAL_SECONDS = 3600  # hourly

# Preview behavior
DEFAULT_PREVIEW_TIMEOUT = 12
DEFAULT_PREVIEW_MAX_CHARS = 1200
DEFAULT_PREVIEW_RATE_LIMIT_SECONDS = 1.25

# Email config persistence (no password stored)
DEFAULT_EMAIL_CFG_PATH = "email.yaml"


# -----------------------------
# Redaction (coordinate-like)
# -----------------------------
# Decimal lat/lon patterns like "34.1234, -118.1234"
RE_DECIMAL_LATLON = re.compile(
    r"(?<!\d)(?:[-+]?([1-8]?\d(?:\.\d+)?|90(?:\.0+)?))\s*,\s*"
    r"(?:[-+]?((?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?|180(?:\.0+)?))(?!\d)"
)

# DMS-ish patterns like 34°12'34"N 118°12'34"W (loose)
RE_DMS = re.compile(
    r"\b\d{1,3}\s*(?:°|deg)\s*\d{1,2}\s*(?:'|min)\s*\d{1,2}(?:\.\d+)?\s*(?:\"|sec)?\s*[NSEW]\b",
    re.IGNORECASE
)

# MGRS-ish (very loose): "38SMB 12345 67890" or "38SMB1234567890"
RE_MGRS = re.compile(r"\b\d{1,2}[C-HJ-NP-X][A-HJ-NP-Z]{2}\s*\d{2,10}\s*\d{2,10}\b", re.IGNORECASE)


def redact_coordinate_like(text: str) -> str:
    if not text:
        return text
    redacted = text
    redacted = RE_DECIMAL_LATLON.sub("[REDACTED_COORDINATES]", redacted)
    redacted = RE_DMS.sub("[REDACTED_COORDINATES]", redacted)
    redacted = RE_MGRS.sub("[REDACTED_COORDINATES]", redacted)
    return redacted


# -----------------------------
# Data models
# -----------------------------
@dataclass(frozen=True)
class Source:
    name: str
    rss_url: str
    trust_tier: int
    tags: List[str]


@dataclass
class Item:
    source_name: str
    title: str
    link: str
    published_utc: Optional[str]
    summary: str
    preview: Optional[str]
    content_hash: str
    inserted_utc: str


@dataclass
class RunStats:
    run_id: int
    total_seen: int
    total_matched: int
    total_inserted: int
    log_path: str
    jsonl_path: Optional[str]


# -----------------------------
# Time helpers
# -----------------------------
def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def fmt_utc(ts: dt.datetime) -> str:
    return ts.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def load_zoneinfo(tz_name: str):
    try:
        from zoneinfo import ZoneInfo  # py3.9+
        return ZoneInfo(tz_name)
    except Exception:
        return None


def now_local(tz_name: str) -> dt.datetime:
    tz = load_zoneinfo(tz_name)
    if tz is None:
        # Fallback: local machine tz
        return dt.datetime.now().astimezone()
    return dt.datetime.now(tz)


def yyyymmdd_hhmm_local(tz_name: str) -> str:
    t = now_local(tz_name)
    return t.strftime("%Y%m%d_%H%M")


# -----------------------------
# Config
# -----------------------------
def load_sources(config_path: str) -> List[Source]:
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    raw_sources = cfg.get("sources", [])
    sources: List[Source] = []
    for s in raw_sources:
        name = str(s.get("name", "")).strip()
        rss_url = str(s.get("rss_url", "")).strip()
        trust_tier = int(s.get("trust_tier", 0))
        tags = s.get("tags", []) or []
        tags = [str(t).strip() for t in tags]
        if not name or not rss_url:
            continue
        sources.append(Source(name=name, rss_url=rss_url, trust_tier=trust_tier, tags=tags))
    return sources


# -----------------------------
# SQLite
# -----------------------------
def db_connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def db_init(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS sources (
      name TEXT PRIMARY KEY,
      rss_url TEXT NOT NULL,
      trust_tier INTEGER NOT NULL,
      tags_json TEXT NOT NULL,
      added_utc TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_name TEXT NOT NULL,
      title TEXT NOT NULL,
      link TEXT NOT NULL,
      published_utc TEXT,
      summary TEXT NOT NULL,
      preview TEXT,
      content_hash TEXT NOT NULL,
      inserted_utc TEXT NOT NULL,
      UNIQUE(source_name, link, content_hash)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_type TEXT NOT NULL,
      local_time TEXT NOT NULL,
      utc_time TEXT NOT NULL,
      keyword TEXT,
      min_trust_tier INTEGER,
      tags_filter_json TEXT,
      with_preview INTEGER NOT NULL,
      interval_seconds INTEGER,
      notes TEXT,
      total_seen INTEGER NOT NULL,
      total_matched INTEGER NOT NULL,
      total_inserted INTEGER NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS run_items (
      run_id INTEGER NOT NULL,
      item_id INTEGER NOT NULL,
      PRIMARY KEY(run_id, item_id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS feed_cache (
      source_name TEXT PRIMARY KEY,
      etag TEXT,
      last_modified TEXT,
      last_status INTEGER,
      last_checked_utc TEXT NOT NULL
    )
    """)

    conn.commit()


def db_upsert_sources(conn: sqlite3.Connection, sources: List[Source]) -> None:
    cur = conn.cursor()
    ts = fmt_utc(now_utc())
    for s in sources:
        cur.execute("""
        INSERT INTO sources(name, rss_url, trust_tier, tags_json, added_utc)
        VALUES(?,?,?,?,?)
        ON CONFLICT(name) DO UPDATE SET
          rss_url=excluded.rss_url,
          trust_tier=excluded.trust_tier,
          tags_json=excluded.tags_json
        """, (s.name, s.rss_url, s.trust_tier, json.dumps(s.tags), ts))
    conn.commit()


def db_get_feed_cache(conn: sqlite3.Connection, source_name: str) -> Dict[str, Any]:
    cur = conn.cursor()
    row = cur.execute("SELECT * FROM feed_cache WHERE source_name=?", (source_name,)).fetchone()
    return dict(row) if row else {}


def db_set_feed_cache(
    conn: sqlite3.Connection,
    source_name: str,
    etag: Optional[str],
    last_modified: Optional[str],
    last_status: int,
) -> None:
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO feed_cache(source_name, etag, last_modified, last_status, last_checked_utc)
    VALUES(?,?,?,?,?)
    ON CONFLICT(source_name) DO UPDATE SET
      etag=excluded.etag,
      last_modified=excluded.last_modified,
      last_status=excluded.last_status,
      last_checked_utc=excluded.last_checked_utc
    """, (source_name, etag, last_modified, int(last_status), fmt_utc(now_utc())))
    conn.commit()


def db_insert_run(
    conn: sqlite3.Connection,
    run_type: str,
    tz_name: str,
    keyword: Optional[str],
    min_trust_tier: Optional[int],
    tags_filter: Optional[List[str]],
    with_preview: bool,
    interval_seconds: Optional[int],
    notes: str,
    total_seen: int,
    total_matched: int,
    total_inserted: int,
) -> int:
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO runs(
      run_type, local_time, utc_time, keyword, min_trust_tier, tags_filter_json,
      with_preview, interval_seconds, notes,
      total_seen, total_matched, total_inserted
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        run_type,
        now_local(tz_name).isoformat(timespec="seconds"),
        fmt_utc(now_utc()),
        keyword,
        min_trust_tier,
        json.dumps(tags_filter or []),
        1 if with_preview else 0,
        interval_seconds,
        notes,
        total_seen,
        total_matched,
        total_inserted,
    ))
    conn.commit()
    return int(cur.lastrowid)


def db_insert_item(conn: sqlite3.Connection, item: Item) -> Optional[int]:
    cur = conn.cursor()
    try:
        cur.execute("""
        INSERT INTO items(
          source_name, title, link, published_utc, summary, preview, content_hash, inserted_utc
        ) VALUES(?,?,?,?,?,?,?,?)
        """, (
            item.source_name, item.title, item.link, item.published_utc,
            item.summary, item.preview, item.content_hash, item.inserted_utc
        ))
        conn.commit()
        return int(cur.lastrowid)
    except sqlite3.IntegrityError:
        return None


def db_link_run_item(conn: sqlite3.Connection, run_id: int, item_id: int) -> None:
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO run_items(run_id, item_id) VALUES(?,?)", (run_id, item_id))
    conn.commit()


def db_get_items_for_run(conn: sqlite3.Connection, run_id: int) -> List[sqlite3.Row]:
    cur = conn.cursor()
    rows = cur.execute("""
      SELECT i.*
      FROM items i
      JOIN run_items ri ON ri.item_id=i.id
      WHERE ri.run_id=?
      ORDER BY COALESCE(i.published_utc, i.inserted_utc) DESC
    """, (run_id,)).fetchall()
    return list(rows)


# -----------------------------
# Fetching
# -----------------------------
class RobotsCache:
    def __init__(self) -> None:
        self._cache: Dict[str, urllib.robotparser.RobotFileParser] = {}

    def allowed(self, url: str, user_agent: str = "ChronicleBot") -> bool:
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        rp = self._cache.get(base)
        if rp is None:
            rp = urllib.robotparser.RobotFileParser()
            rp.set_url(urllib.parse.urljoin(base, "/robots.txt"))
            try:
                rp.read()
            except Exception:
                # If robots can't be fetched, default to disallow preview fetching
                self._cache[base] = rp
                return False
            self._cache[base] = rp
        try:
            return rp.can_fetch(user_agent, url)
        except Exception:
            return False


def fetch_feed(source: Source, conn: sqlite3.Connection, timeout: int = 18) -> Tuple[int, Optional[bytes]]:
    cache = db_get_feed_cache(conn, source.name)
    headers: Dict[str, str] = {"User-Agent": "Chronicle-LF/1.0"}
    if cache.get("etag"):
        headers["If-None-Match"] = str(cache["etag"])
    if cache.get("last_modified"):
        headers["If-Modified-Since"] = str(cache["last_modified"])

    try:
        resp = requests.get(source.rss_url, headers=headers, timeout=timeout)
    except Exception:
        db_set_feed_cache(conn, source.name, cache.get("etag"), cache.get("last_modified"), 0)
        return 0, None

    etag = resp.headers.get("ETag")
    last_mod = resp.headers.get("Last-Modified")
    db_set_feed_cache(conn, source.name, etag, last_mod, resp.status_code)

    if resp.status_code == 304:
        return 304, None
    if resp.status_code != 200:
        return resp.status_code, None
    return 200, resp.content


def normalize_text(s: str) -> str:
    s = (s or "").lower()
    s = re.sub(r"\s+", " ", s).strip()
    return s


def keyword_match(keyword: str, title: str, summary: str) -> bool:
    k = normalize_text(keyword)
    if not k:
        return True
    hay = f"{normalize_text(title)} {normalize_text(summary)}"
    return k in hay


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def extract_entry_published_utc(entry: Any) -> Optional[str]:
    # feedparser provides published_parsed/updated_parsed as time.struct_time
    for key in ("published_parsed", "updated_parsed"):
        v = getattr(entry, key, None) if hasattr(entry, key) else entry.get(key)
        if v:
            try:
                ts = dt.datetime.fromtimestamp(time.mktime(v), tz=dt.timezone.utc)
                return fmt_utc(ts)
            except Exception:
                continue
    return None


def fetch_preview_text(
    url: str,
    robots: RobotsCache,
    timeout: int,
    max_chars: int,
) -> Optional[str]:
    if not robots.allowed(url):
        return None

    try:
        resp = requests.get(url, headers={"User-Agent": "Chronicle-LF/1.0"}, timeout=timeout)
        if resp.status_code != 200 or not resp.text:
            return None
    except Exception:
        return None

    soup = BeautifulSoup(resp.text, "html.parser")
    # remove script/style/nav
    for tag in soup(["script", "style", "nav", "header", "footer", "noscript"]):
        tag.decompose()
    text = soup.get_text(" ", strip=True)
    text = redact_coordinate_like(text)
    if not text:
        return None
    return text[:max_chars]


# -----------------------------
# Clustering (lightweight corroboration)
# -----------------------------
def similarity_ratio(a: str, b: str) -> float:
    # Cheap string similarity using token overlap
    at = set(normalize_text(a).split())
    bt = set(normalize_text(b).split())
    if not at or not bt:
        return 0.0
    inter = len(at & bt)
    union = len(at | bt)
    return inter / union if union else 0.0


def build_clusters(rows: List[sqlite3.Row], threshold: float = 0.55) -> List[List[sqlite3.Row]]:
    clusters: List[List[sqlite3.Row]] = []
    used = set()

    for i, r in enumerate(rows):
        if i in used:
            continue
        base_title = r["title"]
        cluster = [r]
        used.add(i)

        for j in range(i + 1, len(rows)):
            if j in used:
                continue
            if similarity_ratio(base_title, rows[j]["title"]) >= threshold:
                cluster.append(rows[j])
                used.add(j)

        clusters.append(cluster)

    # sort clusters by size desc
    clusters.sort(key=len, reverse=True)
    return clusters


# -----------------------------
# OPLOG / JSONL
# -----------------------------
def ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)


def write_oplog(
    tz_name: str,
    branch: str,
    run_id: int,
    keyword: str,
    interval_seconds: int,
    sources_used: List[Source],
    stats: Dict[str, int],
    run_items: List[sqlite3.Row],
    clusters: List[List[sqlite3.Row]],
) -> str:
    ensure_dir(DEFAULT_LOG_DIR)
    stamp = yyyymmdd_hhmm_local(tz_name)
    path = os.path.join(DEFAULT_LOG_DIR, f"{stamp}_Chronicle-LF_{branch}.log")

    local_ts = now_local(tz_name).isoformat(timespec="seconds")
    utc_ts = fmt_utc(now_utc())

    def line(s: str = "") -> str:
        return s + "\n"

    with open(path, "w", encoding="utf-8") as f:
        f.write(line("CHRONICLE-LF OPLOG"))
        f.write(line("=" * 72))
        f.write(line(f"Run ID           : {run_id}"))
        f.write(line(f"Branch Label     : {branch}"))
        f.write(line(f"Local Time       : {local_ts} ({tz_name})"))
        f.write(line(f"UTC Time         : {utc_ts}"))
        f.write(line(f"Keyword Filter   : {keyword!r}"))
        f.write(line(f"Interval Seconds : {interval_seconds}"))
        f.write(line(""))
        f.write(line("SOURCE ALLOWLIST USED"))
        f.write(line("-" * 72))
        for s in sources_used:
            f.write(line(f"- {s.name} | trust={s.trust_tier} | tags={','.join(s.tags) or '-'} | {s.rss_url}"))
        f.write(line(""))
        f.write(line("RUN SUMMARY"))
        f.write(line("-" * 72))
        f.write(line(f"Feeds checked      : {stats['feeds_checked']}"))
        f.write(line(f"Feeds unchanged(304): {stats['feeds_unchanged']}"))
        f.write(line(f"Total items seen   : {stats['total_seen']}"))
        f.write(line(f"Matched items      : {stats['total_matched']}"))
        f.write(line(f"New items inserted : {stats['total_inserted']}"))
        f.write(line(""))
        f.write(line("CORROBORATION CLUSTERS (lightweight)"))
        f.write(line("-" * 72))
        for idx, c in enumerate(clusters[:25], start=1):
            if len(c) < 2:
                continue
            f.write(line(f"[Cluster {idx}] size={len(c)}"))
            for r in c[:8]:
                f.write(line(f"  - {r['source_name']}: {r['title']} ({r['link']})"))
            if len(c) > 8:
                f.write(line(f"  ... +{len(c) - 8} more"))
            f.write(line(""))

        f.write(line(""))
        f.write(line("MATCHED ITEMS (most recent first)"))
        f.write(line("-" * 72))
        for r in run_items:
            f.write(line(f"Source    : {r['source_name']}"))
            f.write(line(f"Title     : {r['title']}"))
            f.write(line(f"Link      : {r['link']}"))
            f.write(line(f"Published : {r['published_utc'] or '-'}"))
            f.write(line(f"Inserted  : {r['inserted_utc']}"))
            f.write(line(f"Hash      : {r['content_hash']}"))
            summary = r["summary"] or ""
            f.write(line("Summary   : " + (summary[:600] + ("…" if len(summary) > 600 else ""))))
            if r["preview"]:
                prev = r["preview"]
                f.write(line("Preview   : " + (prev[:600] + ("…" if len(prev) > 600 else ""))))
            f.write(line("-" * 72))

    return path


def write_jsonl(
    tz_name: str,
    branch: str,
    run_items: List[sqlite3.Row],
    project: str = "Chronicle-LF",
) -> str:
    stamp = yyyymmdd_hhmm_local(tz_name)
    out_path = f"{stamp}_{project}_{branch}.jsonl"
    with open(out_path, "w", encoding="utf-8") as f:
        for r in run_items:
            obj = dict(r)
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    return out_path


# -----------------------------
# Email
# -----------------------------
@dataclass
class EmailConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_starttls: bool = True
    smtp_ssl: bool = False
    smtp_user: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    smtp_pass_env: str = "CHRONICLE_SMTP_PASS"  # password comes from env var by default


def load_email_config(path: str) -> EmailConfig:
    if not os.path.exists(path):
        return EmailConfig()
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return EmailConfig(
        enabled=bool(data.get("enabled", False)),
        smtp_host=str(data.get("smtp_host", "")),
        smtp_port=int(data.get("smtp_port", 587)),
        smtp_starttls=bool(data.get("smtp_starttls", True)),
        smtp_ssl=bool(data.get("smtp_ssl", False)),
        smtp_user=str(data.get("smtp_user", "")),
        smtp_from=str(data.get("smtp_from", "")),
        smtp_to=str(data.get("smtp_to", "")),
        smtp_pass_env=str(data.get("smtp_pass_env", "CHRONICLE_SMTP_PASS")),
    )


def save_email_config(path: str, cfg: EmailConfig) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(dataclasses.asdict(cfg), f, sort_keys=False)


def send_email_smtp(
    cfg: EmailConfig,
    subject: str,
    body_text: str,
    attachments: Optional[List[Tuple[str, bytes]]] = None,
    smtp_password: Optional[str] = None,
) -> None:
    if not cfg.smtp_host or not cfg.smtp_from or not cfg.smtp_to:
        raise RuntimeError("Email config incomplete (smtp_host/smtp_from/smtp_to required).")

    msg = MIMEMultipart()
    msg["From"] = cfg.smtp_from
    msg["To"] = cfg.smtp_to
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate(localtime=True)

    msg.attach(MIMEText(body_text, "plain", "utf-8"))

    for (filename, content) in (attachments or []):
        part = MIMEApplication(content, Name=filename)
        part["Content-Disposition"] = f'attachment; filename="{filename}"'
        msg.attach(part)

    pwd = smtp_password
    if pwd is None:
        pwd = os.environ.get(cfg.smtp_pass_env, "")

    if cfg.smtp_ssl:
        import smtplib
        with smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=20) as s:
            if cfg.smtp_user:
                s.login(cfg.smtp_user, pwd)
            s.sendmail(cfg.smtp_from, [cfg.smtp_to], msg.as_string())
        return

    import smtplib
    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=20) as s:
        s.ehlo()
        if cfg.smtp_starttls:
            s.starttls()
            s.ehlo()
        if cfg.smtp_user:
            s.login(cfg.smtp_user, pwd)
        s.sendmail(cfg.smtp_from, [cfg.smtp_to], msg.as_string())


# -----------------------------
# Menu
# -----------------------------
def menu_prompt(args: argparse.Namespace, email_cfg_path: str) -> argparse.Namespace:
    email_cfg = load_email_config(email_cfg_path)

    def show_header() -> None:
        print("\n" + "=" * 72)
        print("Chronicle-LF (Live Feed)")
        print("=" * 72)
        print("Default: hourly updates on keyword 'Iran'")
        print("Optional: email forwarding after each cycle\n")

    while True:
        show_header()
        print("Choose an action:")
        print("  [1] Start live feed (hourly, keyword='Iran')  (default)")
        print("  [2] Start live feed (custom keyword / interval)")
        print("  [3] Run ONE cycle now and exit")
        print("  [4] Configure email forwarding (SMTP)")
        print("  [5] Send a test email")
        print("  [6] Quit")
        choice = input("\nSelection (Enter=1): ").strip() or "1"

        if choice == "1":
            args.keyword = "Iran"
            args.interval = 3600
            args.once = False
            return args

        if choice == "2":
            kw = input("Keyword (e.g., Iran): ").strip()
            iv = input("Interval seconds (e.g., 3600): ").strip()
            args.keyword = kw or DEFAULT_KEYWORD
            try:
                args.interval = int(iv) if iv else DEFAULT_INTERVAL_SECONDS
            except ValueError:
                args.interval = DEFAULT_INTERVAL_SECONDS
            args.once = False
            return args

        if choice == "3":
            kw = input("Keyword (e.g., Iran): ").strip()
            args.keyword = kw or DEFAULT_KEYWORD
            args.once = True
            return args

        if choice == "4":
            print("\nEmail forwarding uses SMTP. Password is NOT stored; use an env var.")
            email_cfg.enabled = True
            email_cfg.smtp_host = input(f"SMTP host [{email_cfg.smtp_host or 'smtp.gmail.com'}]: ").strip() or (email_cfg.smtp_host or "smtp.gmail.com")
            port_s = input(f"SMTP port [{email_cfg.smtp_port}]: ").strip()
            if port_s:
                try:
                    email_cfg.smtp_port = int(port_s)
                except ValueError:
                    pass
            tls_s = input(f"Use STARTTLS? (y/n) [{'y' if email_cfg.smtp_starttls else 'n'}]: ").strip().lower()
            if tls_s in ("y", "n"):
                email_cfg.smtp_starttls = (tls_s == "y")
            ssl_s = input(f"Use SSL? (y/n) [{'y' if email_cfg.smtp_ssl else 'n'}]: ").strip().lower()
            if ssl_s in ("y", "n"):
                email_cfg.smtp_ssl = (ssl_s == "y")

            email_cfg.smtp_user = input(f"SMTP username [{email_cfg.smtp_user}]: ").strip() or email_cfg.smtp_user
            email_cfg.smtp_from = input(f"From email [{email_cfg.smtp_from}]: ").strip() or email_cfg.smtp_from
            email_cfg.smtp_to = input(f"To email [{email_cfg.smtp_to}]: ").strip() or email_cfg.smtp_to
            email_cfg.smtp_pass_env = input(f"Password env var [{email_cfg.smtp_pass_env}]: ").strip() or email_cfg.smtp_pass_env

            save_email_config(email_cfg_path, email_cfg)
            print(f"\nSaved email settings to {email_cfg_path} (password not stored).")
            input("Press Enter to continue...")
            continue

        if choice == "5":
            if not email_cfg.enabled:
                print("\nEmail is not enabled yet. Choose [4] first.")
                input("Press Enter to continue...")
                continue

            pwd = os.environ.get(email_cfg.smtp_pass_env, "")
            if not pwd:
                print(f"\nEnv var {email_cfg.smtp_pass_env} is not set.")
                print("You can set it temporarily just for this test.")
                typed = getpass.getpass(f"Enter SMTP password (won't echo) for test: ").strip()
                pwd = typed

            subj = "Chronicle-LF test email"
            body = "This is a test message from Chronicle-LF.\n"
            try:
                send_email_smtp(email_cfg, subj, body, attachments=None, smtp_password=pwd)
                print("\nTest email sent.")
            except Exception as e:
                print(f"\nTest email failed: {e}")
            input("Press Enter to continue...")
            continue

        if choice == "6":
            print("Exiting.")
            raise SystemExit(0)

        print("\nInvalid selection.")
        input("Press Enter to continue...")


# -----------------------------
# Main cycle
# -----------------------------
def filter_sources(
    sources: List[Source],
    min_trust_tier: int,
    tags_filter: Optional[List[str]],
) -> List[Source]:
    tf = set([t.strip().lower() for t in (tags_filter or []) if t.strip()])
    out: List[Source] = []
    for s in sources:
        if s.trust_tier < min_trust_tier:
            continue
        if tf:
            st = set([t.lower() for t in s.tags])
            if not (st & tf):
                continue
        out.append(s)
    return out


def run_cycle(args: argparse.Namespace, email_cfg: EmailConfig) -> RunStats:
    conn = db_connect(args.db)
    db_init(conn)

    sources = load_sources(args.config)
    db_upsert_sources(conn, sources)

    if args.reload_config:
        # already loaded once above; kept for parity
        pass

    sources_used = filter_sources(sources, args.min_trust_tier, args.tags)
    if not sources_used:
        raise RuntimeError("No sources matched filters (min_trust_tier/tags).")

    robots = RobotsCache()

    stats = {
        "feeds_checked": 0,
        "feeds_unchanged": 0,
        "total_seen": 0,
        "total_matched": 0,
        "total_inserted": 0,
    }

    inserted_item_ids: List[int] = []
    inserted_rows_for_email: List[Item] = []

    for src in sources_used:
        stats["feeds_checked"] += 1
        code, content = fetch_feed(src, conn)
        if code == 304:
            stats["feeds_unchanged"] += 1
            continue
        if code != 200 or not content:
            continue

        feed = feedparser.parse(content)
        entries = getattr(feed, "entries", []) or []
        for entry in entries:
            stats["total_seen"] += 1
            title = (entry.get("title") or "").strip()
            link = (entry.get("link") or "").strip()
            summary = (entry.get("summary") or entry.get("description") or "").strip()

            # Redact coordinate-like strings even from summaries
            title = redact_coordinate_like(title)
            summary = redact_coordinate_like(summary)

            if not title and not link:
                continue

            if not keyword_match(args.keyword, title, summary):
                continue
            stats["total_matched"] += 1

            published_utc = extract_entry_published_utc(entry)
            preview_text = None
            if args.with_preview and link:
                preview_text = fetch_preview_text(
                    link,
                    robots=robots,
                    timeout=args.preview_timeout,
                    max_chars=args.preview_max_chars,
                )
                # rate limiting
                time.sleep(max(0.0, float(args.preview_delay)))

            # Content hash (includes preview if present)
            h_basis = f"{src.name}\n{title}\n{link}\n{summary}\n{preview_text or ''}"
            content_hash = sha256_hex(h_basis)

            item = Item(
                source_name=src.name,
                title=title or "(no title)",
                link=link or "(no link)",
                published_utc=published_utc,
                summary=summary or "",
                preview=preview_text,
                content_hash=content_hash,
                inserted_utc=fmt_utc(now_utc()),
            )

            item_id = db_insert_item(conn, item)
            if item_id is not None:
                stats["total_inserted"] += 1
                inserted_item_ids.append(item_id)
                inserted_rows_for_email.append(item)

    # Create run record and link items
    notes = "live feed cycle"
    run_id = db_insert_run(
        conn=conn,
        run_type="LF",
        tz_name=args.tz,
        keyword=args.keyword,
        min_trust_tier=args.min_trust_tier,
        tags_filter=args.tags,
        with_preview=args.with_preview,
        interval_seconds=args.interval,
        notes=notes,
        total_seen=stats["total_seen"],
        total_matched=stats["total_matched"],
        total_inserted=stats["total_inserted"],
    )

    for iid in inserted_item_ids:
        db_link_run_item(conn, run_id, iid)

    run_items = db_get_items_for_run(conn, run_id)
    clusters = build_clusters(run_items)

    log_path = write_oplog(
        tz_name=args.tz,
        branch=args.branch,
        run_id=run_id,
        keyword=args.keyword,
        interval_seconds=args.interval,
        sources_used=sources_used,
        stats=stats,
        run_items=run_items,
        clusters=clusters,
    )

    jsonl_path = None
    if args.export_json:
        jsonl_path = write_jsonl(args.tz, args.branch, run_items)

    # Email forwarding
    should_email = (args.email_mode != "never") and email_cfg.enabled
    if should_email and (args.email_mode == "always" or stats["total_inserted"] > 0):
        subject = f"Chronicle-LF | {args.keyword} | {now_local(args.tz).strftime('%Y-%m-%d %H:%M')} | new={stats['total_inserted']}"
        lines = [
            "Chronicle-LF cycle summary",
            f"- Keyword: {args.keyword}",
            f"- Local : {now_local(args.tz).isoformat(timespec='seconds')} ({args.tz})",
            f"- UTC   : {fmt_utc(now_utc())}",
            f"- New items inserted: {stats['total_inserted']}",
            "",
        ]
        if stats["total_inserted"] > 0:
            lines.append("New items:")
            for it in inserted_rows_for_email[:50]:
                lines.append(f"- {it.source_name}: {it.title}")
                lines.append(f"  {it.link}")
            if len(inserted_rows_for_email) > 50:
                lines.append(f"... +{len(inserted_rows_for_email) - 50} more")
        else:
            lines.append("No new items this cycle.")

        with open(log_path, "rb") as f:
            log_bytes = f.read()

        attachments: List[Tuple[str, bytes]] = [(os.path.basename(log_path), log_bytes)]
        if jsonl_path:
            try:
                with open(jsonl_path, "rb") as jf:
                    attachments.append((os.path.basename(jsonl_path), jf.read()))
            except Exception:
                pass

        send_email_smtp(
            email_cfg,
            subject=subject,
            body_text="\n".join(lines),
            attachments=attachments,
            smtp_password=None,
        )

    conn.close()

    return RunStats(
        run_id=run_id,
        total_seen=stats["total_seen"],
        total_matched=stats["total_matched"],
        total_inserted=stats["total_inserted"],
        log_path=log_path,
        jsonl_path=jsonl_path,
    )


# -----------------------------
# Loop / CLI
# -----------------------------
_STOP = False


def _handle_stop(_sig, _frame):
    global _STOP
    _STOP = True


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="chronicle-lf.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(f"""
        Chronicle-LF: continuous allowlisted RSS archiving with audit-ready OPLOGs.

        Defaults (if you run with no args in a terminal):
          - keyword: {DEFAULT_KEYWORD!r}
          - interval: {DEFAULT_INTERVAL_SECONDS} seconds (hourly)
          - config: {DEFAULT_CONFIG}
          - branch label: {DEFAULT_BRANCH}
          - timezone: {DEFAULT_TZ}
        """).strip(),
    )

    p.add_argument("--config", default=DEFAULT_CONFIG, help="Path to sources.yaml")
    p.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path (default: data/chronicle.db)")
    p.add_argument("--keyword", default=DEFAULT_KEYWORD, help="Keyword filter (case-insensitive substring match)")
    p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SECONDS, help="Loop interval in seconds (default: 3600)")
    p.add_argument("--once", action="store_true", help="Run one cycle and exit")
    p.add_argument("--max-cycles", type=int, default=0, help="Stop after N cycles (0 = unlimited)")
    p.add_argument("--reload-config", action="store_true", help="Reload config each cycle (useful while tuning sources)")
    p.add_argument("--min-trust-tier", type=int, default=0, help="Only use sources with trust_tier >= this value")
    p.add_argument("--tags", nargs="*", default=None, help="Only use sources whose tags intersect these tags")

    p.add_argument("--with-preview", action="store_true", help="Fetch article previews (robots-aware) + redact coordinate-like strings")
    p.add_argument("--preview-timeout", type=int, default=DEFAULT_PREVIEW_TIMEOUT, help="Preview fetch timeout seconds")
    p.add_argument("--preview-max-chars", type=int, default=DEFAULT_PREVIEW_MAX_CHARS, help="Max chars stored for preview text")
    p.add_argument("--preview-delay", type=float, default=DEFAULT_PREVIEW_RATE_LIMIT_SECONDS, help="Delay between preview fetches (seconds)")

    p.add_argument("--export-json", action="store_true", help="Write JSONL export for each cycle")

    p.add_argument("--tz", default=DEFAULT_TZ, help="Timezone label for logs (default: America/Chicago)")
    p.add_argument("--branch", default=DEFAULT_BRANCH, help="Branch label for OPLOG naming (default: USMC)")

    # Email
    p.add_argument("--email-mode", choices=("new", "always", "never"), default="new",
                   help="Email forwarding behavior: new=only if new items, always=every cycle, never=disable")
    p.add_argument("--email-config", default=DEFAULT_EMAIL_CFG_PATH, help="Email config YAML (password not stored)")

    # Menu
    p.add_argument("--menu", action="store_true", help="Show interactive menu (recommended for first run)")

    return p.parse_args(list(argv))


def main(argv: Sequence[str]) -> int:
    global _STOP

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    args = parse_args(argv)

    # If run in a terminal with no meaningful args, show menu by default (simple UX),
    # but keep Enter-to-start-hourly-Iran behavior.
    invoked_with_no_flags = (len(argv) == 0)
    if (args.menu or invoked_with_no_flags) and sys.stdin.isatty():
        args = menu_prompt(args, args.email_config)

    if not os.path.exists(args.config):
        print(f"ERROR: config not found: {args.config}", file=sys.stderr)
        return 2

    email_cfg = load_email_config(args.email_config)

    cycles = 0
    while True:
        if _STOP:
            print("\nStop requested. Exiting.")
            return 0

        if args.reload_config:
            # Ensure config exists each cycle
            if not os.path.exists(args.config):
                print(f"ERROR: config not found: {args.config}", file=sys.stderr)
                return 2

        try:
            stats = run_cycle(args, email_cfg)
        except Exception as e:
            print(f"[cycle error] {e}", file=sys.stderr)
            stats = None

        if stats:
            print(f"Wrote OPLOG: {stats.log_path}")
            print(f"SQLite DB  : {args.db}")
            if stats.jsonl_path:
                print(f"JSONL      : {stats.jsonl_path}")
            print(f"Inserted   : {stats.total_inserted} new items\n")

        cycles += 1
        if args.once:
            return 0
        if args.max_cycles and cycles >= args.max_cycles:
            print(f"Reached max cycles ({args.max_cycles}). Exiting.")
            return 0

        # Sleep until next cycle, with early stop
        sleep_left = max(1, int(args.interval))
        while sleep_left > 0 and not _STOP:
            time.sleep(1)
            sleep_left -= 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
