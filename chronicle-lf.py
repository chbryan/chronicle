#!/usr/bin/env python3
"""
CHRONICLE-LF — Public-Source OSINT Live Feed Archiver (Non-Actionable)

Purpose:
- Continuously ingest public RSS feeds from an explicit allowlist
- Preserve provenance, integrity hashes, and run logs
- Deduplicate and cluster similar reporting for lightweight corroboration

Guardrails (by design):
- No geocoding and no extraction/output of precise coordinates
- Coordinate-like strings (lat/lon, DMS, MGRS-like) are redacted from stored excerpts/logs
- This is an archival/corroboration tool for public reporting, not a targeting/tracking system

Install:
  pip install feedparser requests pyyaml beautifulsoup4

Run (live feed):
  python chronicle-lf.py --config sources.yaml --keyword "Russia" --interval 900 --with-preview

Run once:
  python chronicle-lf.py --config sources.yaml --keyword "Russia" --once

Notes:
- Configure sources in sources.yaml (allowlist).
- Respect site terms; RSS is preferred. Preview fetching is optional and robots-aware.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import random
import re
import signal
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser
from zoneinfo import ZoneInfo

import feedparser
import requests
import yaml
from bs4 import BeautifulSoup


PROJECT_NAME = "Chronicle-LF"
DEFAULT_TZ = "America/Chicago"
DEFAULT_UA = "chronicle-lf/1.1 (+non-actionable; provenance-first)"
DEFAULT_INTERVAL_S = 900  # 15 minutes
DEFAULT_TIMEOUT_S = 15
DEFAULT_PREVIEW_RATE_LIMIT_S = 1.2
DEFAULT_JITTER_PCT = 0.10  # +/-10% jitter on intervals
SCHEMA_VERSION = 2


# ----------------------------
# Safety: redact coordinate-like strings
# ----------------------------
LATLON_RE = re.compile(r"(?:(?P<lat>[+-]?\d{1,2}\.\d{3,})\s*[,;/ ]\s*(?P<lon>[+-]?\d{1,3}\.\d{3,}))")
DMS_RE = re.compile(
    r"""
    (?:
      \d{1,2}\s*[°]\s*\d{1,2}\s*[′']\s*\d{1,2}(?:\.\d+)?\s*[″"]?\s*[NS]
      \s*[,;/ ]\s*
      \d{1,3}\s*[°]\s*\d{1,2}\s*[′']\s*\d{1,2}(?:\.\d+)?\s*[″"]?\s*[EW]
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)
MGRS_RE = re.compile(r"\b\d{1,2}[C-HJ-NP-X][A-HJ-NP-Z]{2}\s*\d{2,10}\s*\d{2,10}\b", re.IGNORECASE)


def redact_sensitive(text: str) -> str:
    if not text:
        return ""
    text = LATLON_RE.sub("[REDACTED-COORDINATES]", text)
    text = DMS_RE.sub("[REDACTED-COORDINATES]", text)
    text = MGRS_RE.sub("[REDACTED-GRIDREF]", text)
    return text


# ----------------------------
# Utilities
# ----------------------------
def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def normalize_ws(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def utc_iso() -> str:
    # timezone-aware UTC; avoids datetime.utcnow() deprecation
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def local_human_and_filestamp(tz_name: str) -> Tuple[str, str]:
    tz = ZoneInfo(tz_name)
    now = datetime.now(tz).replace(microsecond=0)
    return now.strftime("%Y-%m-%d %H:%M:%S"), now.strftime("%Y%m%d_%H%M")


def u64_to_i64(u: int) -> int:
    """Convert unsigned 64-bit to signed int64 (safe for SQLite INTEGER)."""
    u &= (2**64 - 1)
    return u - 2**64 if u >= 2**63 else u


def i64_to_u64(i: int) -> int:
    """Convert signed int64 back to unsigned 64-bit."""
    return i + 2**64 if i < 0 else i


# ----------------------------
# SimHash (light corroboration clustering)
# ----------------------------
def _tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z0-9]{3,}", text.lower())


def simhash64_u(text: str) -> int:
    """
    Returns unsigned 64-bit simhash (0..2^64-1).
    """
    v = [0] * 64
    for tok in _tokenize(text):
        h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)  # nosec (non-crypto use)
        for i in range(64):
            v[i] += 1 if ((h >> i) & 1) else -1

    out = 0
    for i in range(64):
        if v[i] > 0:
            out |= (1 << i)
    return out & (2**64 - 1)


def hamming64_u(a_u: int, b_u: int) -> int:
    return (a_u ^ b_u).bit_count()


def cluster_items_by_simhash(items: List[Dict[str, Any]], max_hamming: int = 3) -> Dict[int, List[int]]:
    """
    Cluster by unsigned simhash u64. Returns clusters keyed by representative simhash u64.
    """
    reps: List[int] = []
    clusters: Dict[int, List[int]] = {}

    for idx, it in enumerate(items):
        sh_u = int(it["simhash_hex"], 16)
        placed = False

        for rep_u in reps:
            if hamming64_u(sh_u, rep_u) <= max_hamming:
                clusters[rep_u].append(idx)
                placed = True
                break

        if not placed:
            reps.append(sh_u)
            clusters[sh_u] = [idx]

    return clusters


# ----------------------------
# robots.txt cache (conservative)
# ----------------------------
class RobotsCache:
    def __init__(self, session: requests.Session, user_agent: str):
        self.session = session
        self.user_agent = user_agent
        self._cache: Dict[str, RobotFileParser] = {}

    def allowed(self, url: str, timeout_s: int = 8) -> bool:
        try:
            p = urlparse(url)
            base = f"{p.scheme}://{p.netloc}"
            if base not in self._cache:
                robots_url = f"{base}/robots.txt"
                rp = RobotFileParser()
                rp.set_url(robots_url)

                r = self.session.get(robots_url, timeout=timeout_s, headers={"User-Agent": self.user_agent})
                if r.status_code >= 400:
                    rp.parse([])  # treat missing robots as allow
                else:
                    rp.parse(r.text.splitlines())

                self._cache[base] = rp

            return self._cache[base].can_fetch(self.user_agent, url)
        except Exception:
            return False


# ----------------------------
# Config
# ----------------------------
@dataclasses.dataclass(frozen=True)
class Source:
    name: str
    rss_url: str
    trust_tier: int = 3
    tags: Tuple[str, ...] = ()


def load_sources(config_path: str) -> List[Source]:
    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    out: List[Source] = []
    for s in data.get("sources", []):
        out.append(
            Source(
                name=str(s["name"]).strip(),
                rss_url=str(s["rss_url"]).strip(),
                trust_tier=int(s.get("trust_tier", 3)),
                tags=tuple(s.get("tags", []) or []),
            )
        )

    if not out:
        raise ValueError("No sources found in sources.yaml")

    return out


# ----------------------------
# DB schema + migrations
# ----------------------------
def connect_db(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA foreign_keys=ON;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.row_factory = sqlite3.Row
    return con


def ensure_db(con: sqlite3.Connection) -> None:
    """
    Creates tables if missing and migrates older schemas.

    Critical fix:
    - items.simhash_i64 + items.simhash_hex added to prevent SQLite INTEGER overflow.
    """
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    con.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1')")

    con.execute(
        """
        CREATE TABLE IF NOT EXISTS sources (
            name TEXT PRIMARY KEY,
            rss_url TEXT NOT NULL,
            trust_tier INTEGER NOT NULL,
            tags TEXT
        )
        """
    )

    con.execute(
        """
        CREATE TABLE IF NOT EXISTS feed_cache (
            source_name TEXT PRIMARY KEY,
            etag TEXT,
            modified TEXT,
            last_status INTEGER,
            last_checked_utc TEXT,
            FOREIGN KEY (source_name) REFERENCES sources(name)
        )
        """
    )

    # Create items table in v2 form if missing
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS items (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            title TEXT NOT NULL,
            link TEXT NOT NULL,
            published TEXT,
            summary TEXT,
            preview TEXT,
            title_hash TEXT NOT NULL,
            link_hash TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            simhash_hex TEXT NOT NULL,
            simhash_i64 INTEGER NOT NULL,
            fetched_at_utc TEXT NOT NULL,
            fetched_at_local TEXT NOT NULL,
            FOREIGN KEY (source) REFERENCES sources(name)
        )
        """
    )

    # Migrate old items that had "simhash INTEGER" only
    cols = {r["name"] for r in con.execute("PRAGMA table_info(items)").fetchall()}
    if "simhash_i64" not in cols or "simhash_hex" not in cols:
        # Add new columns (SQLite supports ADD COLUMN)
        if "simhash_hex" not in cols:
            con.execute("ALTER TABLE items ADD COLUMN simhash_hex TEXT")
        if "simhash_i64" not in cols:
            con.execute("ALTER TABLE items ADD COLUMN simhash_i64 INTEGER")

        cols = {r["name"] for r in con.execute("PRAGMA table_info(items)").fetchall()}
        if "simhash" in cols:
            rows = con.execute("SELECT id, simhash FROM items").fetchall()
            for row in rows:
                old = int(row["simhash"])
                u = i64_to_u64(old) & (2**64 - 1)
                con.execute(
                    "UPDATE items SET simhash_hex=?, simhash_i64=? WHERE id=?",
                    (f"{u:016x}", u64_to_i64(u), row["id"]),
                )
        else:
            # If no legacy simhash, fill defaults
            con.execute(
                "UPDATE items SET simhash_hex=COALESCE(simhash_hex,'0000000000000000'), "
                "simhash_i64=COALESCE(simhash_i64,0)"
            )

        con.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))

    # Indexes (safe after columns exist)
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_items_link_hash ON items(link_hash)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_items_source ON items(source)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_items_fetched_utc ON items(fetched_at_utc)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_items_simhash_i64 ON items(simhash_i64)")
    # (If you kept older idx_items_simhash, it can remain; no harm.)

    con.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            cycle_no INTEGER NOT NULL,
            started_at_utc TEXT NOT NULL,
            finished_at_utc TEXT NOT NULL,
            tz_name TEXT NOT NULL,
            keyword TEXT,
            min_trust_tier INTEGER NOT NULL,
            items_seen INTEGER NOT NULL,
            items_matched INTEGER NOT NULL,
            items_inserted INTEGER NOT NULL,
            config_hash TEXT NOT NULL,
            notes TEXT
        )
        """
    )

    con.execute(
        """
        CREATE TABLE IF NOT EXISTS run_items (
            run_id TEXT NOT NULL,
            item_id TEXT NOT NULL,
            PRIMARY KEY (run_id, item_id),
            FOREIGN KEY (run_id) REFERENCES runs(run_id),
            FOREIGN KEY (item_id) REFERENCES items(id)
        )
        """
    )

    con.commit()


def upsert_sources(con: sqlite3.Connection, sources: Iterable[Source]) -> None:
    for s in sources:
        con.execute(
            """
            INSERT INTO sources (name, rss_url, trust_tier, tags)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                rss_url=excluded.rss_url,
                trust_tier=excluded.trust_tier,
                tags=excluded.tags
            """,
            (s.name, s.rss_url, s.trust_tier, ",".join(s.tags)),
        )
        con.execute(
            """
            INSERT OR IGNORE INTO feed_cache (source_name, etag, modified, last_status, last_checked_utc)
            VALUES (?, NULL, NULL, NULL, NULL)
            """,
            (s.name,),
        )
    con.commit()


def get_feed_cache(con: sqlite3.Connection, source_name: str) -> Tuple[Optional[str], Optional[str]]:
    row = con.execute("SELECT etag, modified FROM feed_cache WHERE source_name=?", (source_name,)).fetchone()
    if not row:
        return None, None
    return row["etag"], row["modified"]


def set_feed_cache(
    con: sqlite3.Connection,
    source_name: str,
    *,
    etag: Optional[str],
    modified: Optional[str],
    last_status: Optional[int],
) -> None:
    con.execute(
        """
        UPDATE feed_cache
        SET etag=?, modified=?, last_status=?, last_checked_utc=?
        WHERE source_name=?
        """,
        (etag, modified, last_status, utc_iso(), source_name),
    )


def insert_item(con: sqlite3.Connection, row: Dict[str, Any]) -> bool:
    try:
        con.execute(
            """
            INSERT INTO items (
                id, source, title, link, published, summary, preview,
                title_hash, link_hash, content_hash,
                simhash_hex, simhash_i64,
                fetched_at_utc, fetched_at_local
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["id"],
                row["source"],
                row["title"],
                row["link"],
                row.get("published"),
                row.get("summary"),
                row.get("preview"),
                row["title_hash"],
                row["link_hash"],
                row["content_hash"],
                row["simhash_hex"],
                row["simhash_i64"],
                row["fetched_at_utc"],
                row["fetched_at_local"],
            ),
        )
        return True
    except sqlite3.IntegrityError:
        return False


def record_run(
    con: sqlite3.Connection,
    *,
    run_id: str,
    cycle_no: int,
    started_at_utc: str,
    finished_at_utc: str,
    tz_name: str,
    keyword: Optional[str],
    min_trust_tier: int,
    items_seen: int,
    items_matched: int,
    items_inserted: int,
    config_hash: str,
    item_ids: List[str],
    notes: str = "",
) -> None:
    con.execute(
        """
        INSERT INTO runs (
            run_id, cycle_no, started_at_utc, finished_at_utc, tz_name,
            keyword, min_trust_tier, items_seen, items_matched, items_inserted, config_hash, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            cycle_no,
            started_at_utc,
            finished_at_utc,
            tz_name,
            keyword,
            min_trust_tier,
            items_seen,
            items_matched,
            items_inserted,
            config_hash,
            notes,
        ),
    )

    for iid in item_ids:
        con.execute("INSERT OR IGNORE INTO run_items (run_id, item_id) VALUES (?, ?)", (run_id, iid))


# ----------------------------
# Fetching feeds (ETag/If-Modified-Since) + previews
# ----------------------------
def fetch_rss(
    session: requests.Session,
    url: str,
    *,
    ua: str,
    timeout_s: int,
    etag: Optional[str],
    modified: Optional[str],
) -> Tuple[int, Optional[str], Optional[str], Optional[bytes]]:
    """
    Returns: (status_code, new_etag, new_modified, content_bytes or None)
    - 304 -> content None
    """
    headers: Dict[str, str] = {"User-Agent": ua}
    if etag:
        headers["If-None-Match"] = etag
    if modified:
        headers["If-Modified-Since"] = modified

    r = session.get(url, timeout=timeout_s, headers=headers)
    status = r.status_code

    new_etag = r.headers.get("ETag") or etag
    new_modified = r.headers.get("Last-Modified") or modified

    if status == 304:
        return status, new_etag, new_modified, None
    if status >= 400:
        return status, new_etag, new_modified, None

    return status, new_etag, new_modified, r.content


def extract_preview(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return normalize_ws(soup.get_text(" "))[:800]


def fetch_preview(
    session: requests.Session,
    url: str,
    *,
    ua: str,
    robots: RobotsCache,
    timeout_s: int,
    rate_limit_s: float,
) -> str:
    if not robots.allowed(url):
        return ""
    time.sleep(rate_limit_s)
    try:
        r = session.get(url, timeout=timeout_s, headers={"User-Agent": ua})
        if r.status_code >= 400:
            return ""
        r.encoding = r.encoding or r.apparent_encoding
        return extract_preview(r.text)
    except Exception:
        return ""


# ----------------------------
# Ingest cycle
# ----------------------------
def ingest_cycle(
    con: sqlite3.Connection,
    sources: List[Source],
    *,
    tz_name: str,
    keyword: Optional[str],
    min_trust_tier: int,
    ua: str,
    timeout_s: int,
    with_preview: bool,
    preview_rate_limit_s: float,
) -> Tuple[int, int, int, List[Dict[str, Any]], Dict[int, List[int]], List[str], str]:
    tz = ZoneInfo(tz_name)
    fetched_local = datetime.now(tz).replace(microsecond=0).isoformat()
    fetched_utc = utc_iso()

    kw = (keyword or "").strip().lower()

    session = requests.Session()
    session.headers.update({"User-Agent": ua})
    robots = RobotsCache(session=session, user_agent=ua)

    items_seen = 0
    matched: List[Dict[str, Any]] = []
    inserted_ids: List[str] = []
    inserted = 0
    notes: List[str] = []

    with con:  # single transaction per cycle
        for s in sources:
            if s.trust_tier < min_trust_tier:
                continue

            etag, modified = get_feed_cache(con, s.name)
            status, new_etag, new_modified, content = fetch_rss(
                session,
                s.rss_url,
                ua=ua,
                timeout_s=timeout_s,
                etag=etag,
                modified=modified,
            )
            set_feed_cache(con, s.name, etag=new_etag, modified=new_modified, last_status=status)

            if status == 304:
                notes.append(f"{s.name}: RSS not modified (304)")
                continue
            if status >= 400 or content is None:
                notes.append(f"{s.name}: RSS fetch failed (status={status})")
                continue

            feed = feedparser.parse(content)

            for e in getattr(feed, "entries", []) or []:
                title = normalize_ws(getattr(e, "title", "") or "")
                link = normalize_ws(getattr(e, "link", "") or "")
                summary = normalize_ws(getattr(e, "summary", "") or "")
                published = normalize_ws(getattr(e, "published", "") or "") or None

                if not title or not link:
                    continue

                items_seen += 1

                haystack = f"{title} {summary}".lower()
                if kw and kw not in haystack:
                    continue

                title_r = redact_sensitive(title)
                summary_r = redact_sensitive(summary)

                preview_txt = ""
                if with_preview:
                    preview_txt = redact_sensitive(
                        fetch_preview(
                            session,
                            link,
                            ua=ua,
                            robots=robots,
                            timeout_s=timeout_s,
                            rate_limit_s=preview_rate_limit_s,
                        )
                    )

                title_hash = sha256(title_r.lower())
                link_hash = sha256(link)
                content_hash = sha256((summary_r + "\n" + preview_txt).strip())

                sh_u64 = simhash64_u(f"{title_r} {summary_r}")
                sh_hex = f"{sh_u64:016x}"
                sh_i64 = u64_to_i64(sh_u64)

                item_id = sha256(f"{s.name}::{link_hash}")

                row: Dict[str, Any] = {
                    "id": item_id,
                    "source": s.name,
                    "title": title_r,
                    "link": link,
                    "published": published,
                    "summary": (summary_r[:2000] if summary_r else None),
                    "preview": (preview_txt[:2000] if preview_txt else None),
                    "title_hash": title_hash,
                    "link_hash": link_hash,
                    "content_hash": content_hash,
                    "simhash_hex": sh_hex,
                    "simhash_i64": sh_i64,
                    "fetched_at_utc": fetched_utc,
                    "fetched_at_local": fetched_local,
                    "trust_tier": s.trust_tier,
                    "tags": list(s.tags),
                }

                did_insert = insert_item(con, row)
                if did_insert:
                    inserted += 1
                    inserted_ids.append(item_id)

                matched.append(row)

    clusters = cluster_items_by_simhash(matched, max_hamming=3)
    return items_seen, len(matched), inserted, matched, clusters, inserted_ids, "\n".join(notes[:200])


# ----------------------------
# OPLOG formatting
# ----------------------------
def format_oplog(
    *,
    branch_label: str,
    tz_name: str,
    keyword: Optional[str],
    min_trust_tier: int,
    sources: List[Source],
    items_seen: int,
    items_matched: int,
    items_inserted: int,
    matched: List[Dict[str, Any]],
    clusters: Dict[int, List[int]],
    run_id: str,
    cycle_no: int,
    started_at_utc: str,
    finished_at_utc: str,
    notes: str,
) -> str:
    local_human, _ = local_human_and_filestamp(tz_name)

    corroborated: List[Tuple[int, List[str], int]] = []
    for rep_u, idxs in clusters.items():
        if len(idxs) < 2:
            continue
        srcs = sorted({matched[i]["source"] for i in idxs})
        corroborated.append((len(idxs), srcs, rep_u))
    corroborated.sort(reverse=True, key=lambda x: x[0])

    lines: List[str] = []
    lines.append("=" * 72)
    lines.append(f"{PROJECT_NAME.upper()} // PUBLIC-SOURCE ARCHIVE OPLOG (NON-ACTIONABLE)")
    lines.append("=" * 72)
    lines.append(f"RUN ID            : {run_id}")
    lines.append(f"CYCLE NO          : {cycle_no}")
    lines.append(f"LOCAL TIME (TZ)   : {local_human}  [{tz_name}]")
    lines.append(f"UTC WINDOW        : {started_at_utc} -> {finished_at_utc}")
    lines.append(f"BRANCH LABEL      : {branch_label}  (metadata label only; not affiliation)")
    lines.append("CLASSIFICATION    : UNCLASSIFIED // OPEN SOURCES ONLY // PRIVATE ARCHIVE")
    lines.append("MISSION           : Archive + provenance + integrity hashes for public reporting.")
    lines.append("GUARDRAILS        : No geocoding; coord-like strings redacted; no real-time tracking.")
    lines.append("-" * 72)
    lines.append(f"FILTER KEYWORD    : {keyword or '(none)'}")
    lines.append(f"MIN TRUST TIER    : {min_trust_tier}")
    lines.append(f"SOURCES IN CONFIG : {len(sources)}")
    lines.append(f"ITEMS SEEN        : {items_seen}")
    lines.append(f"ITEMS MATCHED     : {items_matched}")
    lines.append(f"ITEMS INSERTED    : {items_inserted}")
    if notes.strip():
        lines.append("-" * 72)
        lines.append("FEED NOTES")
        lines.append(notes.strip())
    lines.append("-" * 72)

    lines.append("SOURCE ALLOWLIST (RSS)")
    for s in sources:
        lines.append(f" - {s.name} | trust={s.trust_tier} | tags={','.join(s.tags) or '-'}")
        lines.append(f"   {s.rss_url}")
    lines.append("-" * 72)

    lines.append("CORROBORATION (SIMILAR REPORT CLUSTERS, MULTI-SOURCE)")
    if corroborated:
        for n, srcs, rep_u in corroborated[:15]:
            lines.append(f" - CLUSTER size={n} sources={len(srcs)} simhash_u64=0x{rep_u:016x}")
            lines.append(f"   SOURCES: {', '.join(srcs)}")
    else:
        lines.append(" - None detected in this cycle.")
    lines.append("-" * 72)

    lines.append("MATCHED ITEMS (VERIFY AT ORIGIN)")
    for idx, it in enumerate(matched, start=1):
        lines.append(f"[{idx:03d}] SOURCE     : {it['source']} (trust={it['trust_tier']})")
        lines.append(f"      TITLE      : {it['title']}")
        if it.get("published"):
            lines.append(f"      PUBLISHED  : {it['published']}")
        lines.append(f"      LINK       : {it['link']}")
        if it.get("summary"):
            lines.append(f"      SUMMARY    : {it['summary']}")
        if it.get("preview"):
            lines.append(f"      PREVIEW    : {it['preview']}")
        lines.append(f"      INTEGRITY  : title_sha256={it['title_hash']}")
        lines.append(f"                  link_sha256={it['link_hash']}")
        lines.append(f"                  content_sha256={it['content_hash']}")
        lines.append(f"      SIMHASH64  : 0x{it['simhash_hex']}")
        lines.append(f"      FETCHED    : utc={it['fetched_at_utc']} local={it['fetched_at_local']}")
        lines.append("")

    lines.append("-" * 72)
    lines.append("END OF OPLOG")
    lines.append("=" * 72)
    return "\n".join(lines)


# ----------------------------
# Loop control
# ----------------------------
STOP = False


def _handle_stop(signum, frame):
    global STOP
    STOP = True


def jittered_interval(base_s: int, jitter_pct: float) -> float:
    if jitter_pct <= 0:
        return float(base_s)
    delta = base_s * jitter_pct
    return max(5.0, random.uniform(base_s - delta, base_s + delta))


# ----------------------------
# Main
# ----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(prog="chronicle-lf", description="Chronicle-LF — live feed public-source archiver.")
    ap.add_argument("--config", default="sources.yaml", help="YAML config path containing RSS allowlist.")
    ap.add_argument("--db", default="data/chronicle.db", help="SQLite DB path.")
    ap.add_argument("--outdir", default="logs", help="Directory for per-cycle logs.")
    ap.add_argument("--keyword", default="", help="Optional filter on title+summary.")
    ap.add_argument("--min-trust-tier", type=int, default=3, help="Only ingest sources >= this trust tier.")
    ap.add_argument("--tz", default=DEFAULT_TZ, help="IANA timezone (default America/Chicago).")
    ap.add_argument("--branch", default="USMC", help="Branch label metadata (e.g., USMC).")
    ap.add_argument("--user-agent", default=DEFAULT_UA, help="HTTP User-Agent string.")
    ap.add_argument("--with-preview", action="store_true", help="Fetch short page preview when robots allows.")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S, help="HTTP timeout seconds.")
    ap.add_argument("--preview-rate", type=float, default=DEFAULT_PREVIEW_RATE_LIMIT_S, help="Seconds between preview fetches.")
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_S, help="Seconds between cycles (live feed).")
    ap.add_argument("--jitter", type=float, default=DEFAULT_JITTER_PCT, help="Interval jitter fraction (0.10 = +/-10%).")
    ap.add_argument("--max-cycles", type=int, default=0, help="Stop after N cycles (0 = run until interrupted).")
    ap.add_argument("--once", action="store_true", help="Run a single cycle and exit.")
    ap.add_argument("--export-json", action="store_true", help="Export matched items for each cycle as JSONL.")
    ap.add_argument("--reload-config", action="store_true", help="Reload sources.yaml each cycle (useful during tuning).")
    args = ap.parse_args()

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    os.makedirs(args.outdir, exist_ok=True)

    # Load config
    sources = load_sources(args.config)
    with open(args.config, "r", encoding="utf-8") as f:
        config_text = f.read()
    config_hash = sha256(config_text)

    cycle_no = 0

    with closing(connect_db(args.db)) as con:
        ensure_db(con)
        upsert_sources(con, sources)

        while True:
            if STOP:
                print("Stop requested. Exiting.")
                break

            cycle_no += 1

            if args.reload_config:
                try:
                    sources = load_sources(args.config)
                    upsert_sources(con, sources)
                    with open(args.config, "r", encoding="utf-8") as f:
                        config_text = f.read()
                    config_hash = sha256(config_text)
                except Exception as e:
                    print(f"[WARN] Failed to reload config: {e}")

            started_at_utc = utc_iso()
            run_id = sha256(f"{started_at_utc}::{config_hash}::{args.keyword}::{args.min_trust_tier}::{cycle_no}")[:16]

            items_seen, items_matched, items_inserted, matched, clusters, inserted_ids, notes = ingest_cycle(
                con,
                sources,
                tz_name=args.tz,
                keyword=(args.keyword.strip() or None),
                min_trust_tier=args.min_trust_tier,
                ua=args.user_agent,
                timeout_s=args.timeout,
                with_preview=bool(args.with_preview),
                preview_rate_limit_s=args.preview_rate,
            )

            finished_at_utc = utc_iso()

            with con:
                record_run(
                    con,
                    run_id=run_id,
                    cycle_no=cycle_no,
                    started_at_utc=started_at_utc,
                    finished_at_utc=finished_at_utc,
                    tz_name=args.tz,
                    keyword=(args.keyword.strip() or None),
                    min_trust_tier=args.min_trust_tier,
                    items_seen=items_seen,
                    items_matched=items_matched,
                    items_inserted=items_inserted,
                    config_hash=config_hash,
                    item_ids=inserted_ids,
                    notes=notes,
                )

            oplog = format_oplog(
                branch_label=args.branch,
                tz_name=args.tz,
                keyword=(args.keyword.strip() or None),
                min_trust_tier=args.min_trust_tier,
                sources=sources,
                items_seen=items_seen,
                items_matched=items_matched,
                items_inserted=items_inserted,
                matched=matched,
                clusters=clusters,
                run_id=run_id,
                cycle_no=cycle_no,
                started_at_utc=started_at_utc,
                finished_at_utc=finished_at_utc,
                notes=notes,
            )

            _, file_stamp = local_human_and_filestamp(args.tz)
            safe_branch = re.sub(r"[^A-Za-z0-9_-]+", "", (args.branch.strip() or "NA"))
            log_name = f"{file_stamp}_{PROJECT_NAME}_{safe_branch}.log"
            log_path = os.path.join(args.outdir, log_name)
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(oplog)

            print(f"[cycle {cycle_no}] wrote: {log_path} | seen={items_seen} matched={items_matched} inserted={items_inserted}")

            if args.export_json:
                jpath = os.path.join(args.outdir, f"{file_stamp}_{PROJECT_NAME}_{safe_branch}.jsonl")
                with open(jpath, "w", encoding="utf-8") as jf:
                    for it in matched:
                        jf.write(json.dumps(it, ensure_ascii=False) + "\n")
                print(f"[cycle {cycle_no}] export: {jpath}")

            if args.once:
                break
            if args.max_cycles and cycle_no >= args.max_cycles:
                break

            sleep_s = jittered_interval(args.interval, args.jitter)
            end = time.time() + sleep_s
            while time.time() < end:
                if STOP:
                    break
                time.sleep(0.5)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
