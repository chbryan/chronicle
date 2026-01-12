#!/usr/bin/env python3
"""
CHRONICLE — Public-Source OSINT Archiver (Non-Actionable)

Core goals:
- Archive public reporting with provenance + integrity hashes.
- Deduplicate and cluster similar stories for cross-source corroboration.
- Generate a professional single-run log file named with date + 24h time.

Explicit guardrails:
- No geocoding, no coordinate output, no real-time force tracking.
- Redacts coordinate-like strings from stored excerpts/logs.

Dependencies:
  pip install feedparser requests pyyaml beautifulsoup4
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
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


DEFAULT_TZ = "America/Chicago"
DEFAULT_UA = "chronicle-osint-archiver/1.1 (+non-actionable; provenance-first)"
DEFAULT_RATE_LIMIT_S = 1.2


# ----------------------------
# Safety: redact coordinate-like strings
# ----------------------------
LATLON_RE = re.compile(
    r"""
    (?:
      (?P<lat>[+-]?\d{1,2}\.\d{3,})\s*[,;/ ]\s*(?P<lon>[+-]?\d{1,3}\.\d{3,})
    )
    """,
    re.VERBOSE,
)

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

# Rough MGRS-ish pattern (redact obvious patterns)
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
    # timezone-aware UTC (fixes utcnow() deprecation warning)
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def local_stamp(tz_name: str) -> Tuple[str, str]:
    tz = ZoneInfo(tz_name)
    now = datetime.now(tz).replace(microsecond=0)
    return now.strftime("%Y-%m-%d %H:%M:%S"), now.strftime("%Y%m%d_%H%M")


def u64_to_i64(u: int) -> int:
    """Store unsigned 64-bit values safely in SQLite INTEGER (signed int64)."""
    u &= (2**64 - 1)
    return u - 2**64 if u >= 2**63 else u


def i64_to_u64(i: int) -> int:
    """Convert signed int64 back to unsigned 64-bit."""
    return i + 2**64 if i < 0 else i


# ----------------------------
# SimHash for lightweight corroboration clustering
# ----------------------------
def _tokenize(text: str) -> List[str]:
    text = text.lower()
    return re.findall(r"[a-z0-9]{3,}", text)


def simhash64(text: str) -> int:
    """
    Basic 64-bit SimHash for near-duplicate clustering.

    NOTE: Returned value is UNSIGNED 64-bit in Python int range [0, 2^64).
    """
    v = [0] * 64
    for tok in _tokenize(text):
        # 128-bit md5; we only use lower 64 bits for our vector tally
        h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)  # nosec (non-crypto use)
        for i in range(64):
            bit = (h >> i) & 1
            v[i] += 1 if bit else -1

    out = 0
    for i in range(64):
        if v[i] > 0:
            out |= (1 << i)

    return out & (2**64 - 1)


def hamming64_u(a_u64: int, b_u64: int) -> int:
    return (a_u64 ^ b_u64).bit_count()


# ----------------------------
# Robots.txt cache
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
                # If robots missing / blocked, default allow (common web convention)
                if r.status_code >= 400:
                    rp.parse([])
                else:
                    rp.parse(r.text.splitlines())

                self._cache[base] = rp

            rp = self._cache[base]
            return rp.can_fetch(self.user_agent, url)
        except Exception:
            # If anything goes wrong fetching/parsing robots, be conservative
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


def load_sources(path: str) -> List[Source]:
    with open(path, "r", encoding="utf-8") as f:
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
# DB schema
# ----------------------------
SCHEMA_VERSION = 2


def connect_db(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA foreign_keys=ON;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.row_factory = sqlite3.Row
    return con


def ensure_db(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    con.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )

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

    # v2: store simhash both as TEXT (hex) and INTEGER (signed int64) to avoid overflow.
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

    con.execute("CREATE INDEX IF NOT EXISTS idx_items_source ON items(source)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_items_fetched_utc ON items(fetched_at_utc)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_items_simhash_i64 ON items(simhash_i64)")
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_items_link_hash ON items(link_hash)")

    con.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            started_at_utc TEXT NOT NULL,
            finished_at_utc TEXT NOT NULL,
            tz_name TEXT NOT NULL,
            keyword TEXT,
            min_trust_tier INTEGER NOT NULL,
            items_seen INTEGER NOT NULL,
            items_matched INTEGER NOT NULL,
            items_inserted INTEGER NOT NULL,
            config_hash TEXT NOT NULL
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
    con.commit()


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
    cycle_no: int = 0,  # <-- add this (single-run uses 0)
) -> None:
    cols = {r["name"] for r in con.execute("PRAGMA table_info(runs)").fetchall()}

    if "cycle_no" in cols:
        con.execute(
            """
            INSERT INTO runs (
                run_id, cycle_no, started_at_utc, finished_at_utc, tz_name, keyword,
                min_trust_tier, items_seen, items_matched, items_inserted, config_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )
    else:
        con.execute(
            """
            INSERT INTO runs (
                run_id, started_at_utc, finished_at_utc, tz_name, keyword,
                min_trust_tier, items_seen, items_matched, items_inserted, config_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                started_at_utc,
                finished_at_utc,
                tz_name,
                keyword,
                min_trust_tier,
                items_seen,
                items_matched,
                items_inserted,
                config_hash,
            ),
        )

    for iid in item_ids:
        con.execute(
            "INSERT OR IGNORE INTO run_items (run_id, item_id) VALUES (?, ?)",
            (run_id, iid),
        )

    con.commit()



# ----------------------------
# Fetching + preview extraction
# ----------------------------
def extract_preview(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = normalize_ws(soup.get_text(" "))
    return text[:800]


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
        # Requests will decode based on headers; fall back to apparent encoding if needed
        r.encoding = r.encoding or r.apparent_encoding
        return extract_preview(r.text)
    except Exception:
        return ""


def fetch_rss(session: requests.Session, rss_url: str, *, ua: str, timeout_s: int) -> feedparser.FeedParserDict:
    """
    Fetch RSS ourselves so we can set UA and timeouts, then parse bytes with feedparser.
    """
    try:
        r = session.get(rss_url, timeout=timeout_s, headers={"User-Agent": ua})
        if r.status_code >= 400:
            return feedparser.FeedParserDict(entries=[])
        return feedparser.parse(r.content)
    except Exception:
        return feedparser.FeedParserDict(entries=[])


# ----------------------------
# Ingest + correlate
# ----------------------------
def cluster_items_by_simhash(items: List[Dict[str, Any]], max_hamming: int = 3) -> Dict[int, List[int]]:
    """
    Returns clusters keyed by a representative *unsigned* simhash u64.
    Each value is list of indices in `items`.
    """
    reps: List[int] = []
    clusters: Dict[int, List[int]] = {}

    for idx, it in enumerate(items):
        sh_u = int(it["simhash_hex"], 16) if "simhash_hex" in it else int(it["simhash_u64"])
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


def ingest(
    con: sqlite3.Connection,
    sources: List[Source],
    *,
    keyword: Optional[str],
    min_trust_tier: int,
    tz_name: str,
    ua: str,
    with_preview: bool,
    timeout_s: int,
    rate_limit_s: float,
    max_items_per_source: int,
) -> Tuple[int, int, int, List[Dict[str, Any]], Dict[int, List[int]], List[str]]:
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

    # Single transaction for speed + integrity
    with con:
        for s in sources:
            if s.trust_tier < min_trust_tier:
                continue

            feed = fetch_rss(session, s.rss_url, ua=ua, timeout_s=timeout_s)
            per_source = 0

            for e in getattr(feed, "entries", []) or []:
                if per_source >= max_items_per_source:
                    break

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

                # Redact coordinate-like strings from excerpts immediately
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
                            rate_limit_s=rate_limit_s,
                        )
                    )

                title_hash = sha256(title_r.lower())
                link_hash = sha256(link)
                content_hash = sha256((summary_r + "\n" + preview_txt).strip())

                sh_u64 = simhash64(f"{title_r} {summary_r}")
                sh_hex = f"{sh_u64:016x}"
                sh_i64 = u64_to_i64(sh_u64)  # FIX: prevents SQLite INTEGER overflow

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
                per_source += 1

    clusters = cluster_items_by_simhash(matched, max_hamming=3)
    return items_seen, len(matched), inserted, matched, clusters, inserted_ids


# ----------------------------
# Log formatting (“OPLOG style”)
# ----------------------------
def format_oplog(
    *,
    project_name: str,
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
    started_at_utc: str,
    finished_at_utc: str,
) -> Tuple[str, str]:
    local_human, local_file = local_stamp(tz_name)

    # Corroboration summary: cluster sizes with multiple sources
    corroborated: List[Tuple[int, List[str], int]] = []
    for rep_u, idxs in clusters.items():
        if len(idxs) < 2:
            continue
        srcs = sorted({matched[i]["source"] for i in idxs})
        corroborated.append((len(idxs), srcs, rep_u))
    corroborated.sort(reverse=True, key=lambda x: x[0])

    lines: List[str] = []
    lines.append("=" * 68)
    lines.append(f"{project_name.upper()} // PUBLIC-SOURCE ARCHIVE OPLOG (NON-ACTIONABLE)")
    lines.append("=" * 68)
    lines.append(f"RUN ID            : {run_id}")
    lines.append(f"LOCAL TIME (TZ)   : {local_human}  [{tz_name}]")
    lines.append(f"UTC WINDOW        : {started_at_utc} -> {finished_at_utc}")
    lines.append(f"BRANCH LABEL      : {branch_label}  (metadata label only; not affiliation)")
    lines.append("CLASSIFICATION    : UNCLASSIFIED // OPEN SOURCES ONLY // PRIVATE TOOLING")
    lines.append("MISSION           : Archive + provenance + integrity hashes for public reporting.")
    lines.append("GUARDRAILS        : No geocoding; coord-like strings redacted; no real-time tracking.")
    lines.append("-" * 68)
    lines.append(f"FILTER KEYWORD    : {keyword or '(none)'}")
    lines.append(f"MIN TRUST TIER    : {min_trust_tier} (source allowlist scoring)")
    lines.append(f"SOURCES IN CONFIG : {len(sources)}")
    lines.append(f"ITEMS SEEN        : {items_seen}")
    lines.append(f"ITEMS MATCHED     : {items_matched}")
    lines.append(f"ITEMS INSERTED    : {items_inserted}")
    lines.append("-" * 68)

    lines.append("SOURCE ALLOWLIST (RSS)")
    for s in sources:
        lines.append(f" - {s.name} | trust={s.trust_tier} | tags={','.join(s.tags) or '-'}")
        lines.append(f"   {s.rss_url}")
    lines.append("-" * 68)

    lines.append("CORROBORATION (SIMILAR REPORT CLUSTERS, MULTI-SOURCE)")
    if corroborated:
        for n, srcs, rep_u in corroborated[:15]:
            lines.append(f" - CLUSTER size={n} sources={len(srcs)} simhash_u64=0x{rep_u:016x}")
            lines.append(f"   SOURCES: {', '.join(srcs)}")
    else:
        lines.append(" - None detected in this run.")
    lines.append("-" * 68)

    lines.append("MATCHED ITEMS (OPEN SOURCE; VERIFY AT ORIGIN)")
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

    lines.append("-" * 68)
    lines.append("END OF OPLOG")
    lines.append("=" * 68)
    return "\n".join(lines), local_file


# ----------------------------
# Main
# ----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(prog="chronicle", description="Chronicle — public-source archive (non-actionable).")
    ap.add_argument("--config", default="sources.yaml", help="YAML config path containing RSS allowlist.")
    ap.add_argument("--db", default="data/chronicle.db", help="SQLite DB path.")
    ap.add_argument("--outdir", default="logs", help="Directory for single-run log output.")
    ap.add_argument("--keyword", default="", help="Optional filter on title+summary.")
    ap.add_argument("--min-trust-tier", type=int, default=3, help="Only ingest sources >= this trust tier.")
    ap.add_argument("--tz", default=DEFAULT_TZ, help="IANA timezone (default America/Chicago).")
    ap.add_argument("--branch", default="USMC", help="Branch label metadata (e.g., USMC).")
    ap.add_argument("--with-preview", action="store_true", help="Fetch short page preview when robots allows.")
    ap.add_argument("--timeout", type=int, default=12, help="HTTP timeout seconds.")
    ap.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT_S, help="Delay between preview fetches.")
    ap.add_argument("--user-agent", default=DEFAULT_UA, help="HTTP User-Agent string.")
    ap.add_argument("--export-json", action="store_true", help="Export matched items for this run as JSONL.")
    ap.add_argument("--max-items-per-source", type=int, default=200, help="Cap items processed per source (safety).")
    args = ap.parse_args()

    project_name = "Chronicle"
    os.makedirs(args.outdir, exist_ok=True)

    sources = load_sources(args.config)

    # Hash config for auditability
    with open(args.config, "r", encoding="utf-8") as f:
        config_text = f.read()
    config_hash = sha256(config_text)

    started_at_utc = utc_iso()
    run_id = sha256(f"{started_at_utc}::{config_hash}::{args.keyword}::{args.min_trust_tier}")[:16]

    with closing(connect_db(args.db)) as con:
        ensure_db(con)
        upsert_sources(con, sources)

        items_seen, items_matched, items_inserted, matched, clusters, inserted_ids = ingest(
            con,
            sources,
            keyword=(args.keyword.strip() or None),
            min_trust_tier=args.min_trust_tier,
            tz_name=args.tz,
            ua=args.user_agent,
            with_preview=bool(args.with_preview),
            timeout_s=args.timeout,
            rate_limit_s=args.rate_limit,
            max_items_per_source=max(1, args.max_items_per_source),
        )

        finished_at_utc = utc_iso()

        record_run(
    con,
    run_id=run_id,
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
    cycle_no=0,  # <-- add
)

    oplog, local_file_stamp = format_oplog(
        project_name=project_name,
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
        started_at_utc=started_at_utc,
        finished_at_utc=finished_at_utc,
    )

    # filename: YYYYMMDD_HHMM_PROJECT_BRANCH.log
    safe_branch = re.sub(r"[^A-Za-z0-9_-]+", "", args.branch.strip() or "NA")
    fname = f"{local_file_stamp}_{project_name}_{safe_branch}.log"
    fpath = os.path.join(args.outdir, fname)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(oplog)

    print(f"Wrote OPLOG: {fpath}")
    print(f"SQLite DB  : {args.db}")

    if args.export_json:
        jpath = os.path.join(args.outdir, f"{local_file_stamp}_{project_name}_{safe_branch}.jsonl")
        with open(jpath, "w", encoding="utf-8") as jf:
            for it in matched:
                jf.write(json.dumps(it, ensure_ascii=False) + "\n")
        print(f"Export JSONL: {jpath}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
