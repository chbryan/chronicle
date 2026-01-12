````markdown
# Chronicle

**Chronicle** is a compliance-first **public-source archiver** for OSINT-style workflows. It ingests **explicitly allowlisted RSS feeds**, preserves **provenance** and **integrity hashes**, deduplicates and **clusters similar reporting** for lightweight corroboration, and produces **professional, audit-friendly run logs**.

> **Important Guardrails (by design)**
>
> - **No geocoding** and **no extraction/output of precise coordinates**
> - **No real-time force/ship tracking**
> - Coordinate-like strings (lat/lon, DMS, MGRS-like patterns) are **redacted** from stored excerpts and logs
> - This is an archival + corroboration tool for **public reporting**, not a targeting system

---
# PM-Note: Switch environment.
```
source .venv/bin/activate
```
---
## Contents

- [What’s Included](#whats-included)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [chronicle.py](#chroniclepy)
  - [Use Cases](#use-cases-chroniclepy)
  - [Example Commands](#example-commands-chroniclepy)
- [chronicle-lf.py (Live Feed)](#chronicle-lfpy-live-feed)
  - [Use Cases](#use-cases-chronicle-lfpy)
  - [Example Commands](#example-commands-chronicle-lfpy)
- [Output](#output)
  - [Log Files](#log-files)
  - [SQLite Database](#sqlite-database)
  - [JSONL Export](#jsonl-export)
- [Trust Tiers & Source Hygiene](#trust-tiers--source-hygiene)
- [Operational Notes](#operational-notes)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## What’s Included

- `chronicle.py`
  - Single-run ingestion + OPLOG report generation
  - Best for ad-hoc research snapshots and audits

- `chronicle-lf.py`
  - Live feed ingestion loop with interval scheduling
  - Best for continuous collection (still non-actionable)

- `sources.yaml`
  - RSS allowlist + source trust tiers + tags

- `data/chronicle.db`
  - SQLite database with items, runs, and (in live feed) feed caching metadata

---

## Quick Start

### 1) Install dependencies

```bash
pip install feedparser requests pyyaml beautifulsoup4
````

### 2) Create your allowlist: `sources.yaml`

Example:

```yaml
sources:
  - name: "NATO Press"
    rss_url: "https://www.nato.int/cps/en/natohq/rss/news.rss"
    trust_tier: 5
    tags: ["official", "press"]

  - name: "UN News"
    rss_url: "https://news.un.org/feed/subscribe/en/news/all/rss.xml"
    trust_tier: 4
    tags: ["official", "international"]
```

### 3) Run a one-time archive snapshot (Chronicle)

```bash
python chronicle.py --config sources.yaml --keyword "Russia" --with-preview --export-json
```

### 4) Run the live feed (Chronicle-LF)

```bash
python chronicle-lf.py --config sources.yaml --keyword "Russia" --interval 900 --with-preview
```

---

## Configuration

### `sources.yaml`

Each source supports:

* `name` (string) — display label / primary key in DB
* `rss_url` (string) — RSS feed URL
* `trust_tier` (int) — your scoring (higher = more trusted)
* `tags` (list[str]) — optional labels for filtering/organization

Example:

```yaml
sources:
  - name: "Example Source"
    rss_url: "https://example.com/rss.xml"
    trust_tier: 3
    tags: ["media", "regional"]
```

---

## `chronicle.py`

`chronicle.py` runs **once**, ingests allowlisted RSS feeds, stores new items, and produces a single OPLOG report.

### Use Cases (chronicle.py)

1. **Daily or weekly “research snapshot”**

   * Capture what reputable sources reported within the last run
   * Store everything with integrity hashes for later reference

2. **Audit-ready archival**

   * Maintain a record of what was publicly reported at a point in time
   * Verify whether an item changed by comparing stored hashes

3. **Corroboration-first review**

   * Identify when multiple sources appear to report the same story
   * Cluster similar items to reduce noise and highlight convergence

4. **Team handoff bundle**

   * Produce a single professional log file + JSONL export to share internally
   * Keep the database locally for repeatable analysis

### Example Commands (chronicle.py)

Run with preview fetching (robots-aware) and JSONL export:

```bash
python chronicle.py --config sources.yaml --keyword "Russia" --with-preview --export-json
```

Require higher-trust sources only:

```bash
python chronicle.py --config sources.yaml --min-trust-tier 4 --keyword "sanctions"
```

Change timezone and branch label metadata:

```bash
python chronicle.py --config sources.yaml --tz "America/Chicago" --branch "USMC"
```

Disable preview fetching (faster, pure RSS):

```bash
python chronicle.py --config sources.yaml --keyword "Black Sea"
```

---

## `chronicle-lf.py` (Live Feed)

`chronicle-lf.py` runs in a **continuous loop**, executing ingestion cycles at your chosen interval. It uses **ETag / If-Modified-Since** to avoid re-downloading unchanged feeds and generates one OPLOG per cycle.

### Use Cases (chronicle-lf.py)

1. **Continuous public-source collection (non-actionable)**

   * Maintain an always-growing archive of public reporting
   * Capture updates as they appear in RSS feeds

2. **Monitoring themes over time**

   * Track recurring topics (e.g., sanctions, diplomacy, conflict reporting)
   * Use keyword filtering to reduce noise

3. **Event timeline construction**

   * Build a time-indexed record of how narratives evolve
   * Preserve original links, timestamps, and hashes for traceability

4. **Research operations workflow**

   * Keep a rolling set of OPLOGs in `logs/`
   * Store all items + run metadata in SQLite for later analysis

### Example Commands (chronicle-lf.py)

Live feed every 15 minutes:

```bash
python chronicle-lf.py --config sources.yaml --keyword "Russia" --interval 900 --with-preview
```

Run a single cycle and exit:

```bash
python chronicle-lf.py --config sources.yaml --keyword "Russia" --once --export-json
```

Run 10 cycles, reload config each cycle (useful while tuning sources):

```bash
python chronicle-lf.py --config sources.yaml --keyword "Russia" --interval 600 --max-cycles 10 --reload-config
```

Increase trust threshold:

```bash
python chronicle-lf.py --config sources.yaml --min-trust-tier 5 --interval 1800
```

---

## Output

### Log Files

Each run/cycle generates an OPLOG-style report in `logs/`:

* **Chronicle**: `YYYYMMDD_HHMM_Chronicle_<BRANCH>.log`
* **Chronicle-LF**: `YYYYMMDD_HHMM_Chronicle-LF_<BRANCH>.log`

Key OPLOG sections:

* run metadata (local + UTC times, run/cycle identifiers)
* source allowlist (with trust tiers/tags)
* corroboration clusters (similar reporting across sources)
* matched items + provenance + integrity hashes

### SQLite Database

Default path: `data/chronicle.db`

Stores:

* `sources` — configured allowlist and trust tiers
* `items` — archived RSS items and optional previews (redacted for coordinate-like strings)
* `runs` — run metadata (timestamps, filters, counts)
* `run_items` — link table between runs and items
* `feed_cache` (Chronicle-LF) — ETag/Last-Modified + last status per feed

### JSONL Export

Optional, per run/cycle:

* `YYYYMMDD_HHMM_<PROJECT>_<BRANCH>.jsonl`

Each line is a JSON object containing:

* source, title, link, published, summary/preview excerpts
* integrity hashes
* simhash value
* fetched timestamps
* trust tier and tags

---

## Trust Tiers & Source Hygiene

`trust_tier` is your local policy tool. Recommended approach:

* **5**: primary official sources (government / intergovernmental bodies)
* **4**: high-quality institutional reporting
* **3**: reputable media / established research organizations
* **2**: niche blogs or less consistent sources (use with caution)
* **1**: low-confidence sources (generally avoid)

**Best practice:** Keep the allowlist tight. Add sources intentionally and audit periodically.

---

## Operational Notes

* **Robots awareness:** Preview fetching uses robots.txt checks and will skip preview collection when disallowed.
* **Rate limiting:** Preview fetching enforces a delay to reduce load on origin sites.
* **ETag caching (LF only):** Live feed avoids re-fetching unchanged RSS feeds when possible.
* **Redaction:** Coordinate-like strings are automatically redacted from stored summaries/previews/logs.

---

## Troubleshooting

### “No sources found in sources.yaml”

* Confirm your YAML structure:

  * Top-level key must be `sources:`
  * Each entry must have `name` and `rss_url`

### “RSS fetch failed”

* The feed may be down, blocked, or require a different URL.
* Try opening the RSS link in a browser.
* Some sites provide RSS only via specific endpoints.

### Preview text is empty

* Preview fetching is optional and robots-aware.
* If robots.txt disallows fetching, previews are skipped.
* Some sites block automated requests; try disabling `--with-preview`.

### Too many duplicate items

* Increase `--min-trust-tier` and refine your allowlist.
* Use more specific `--keyword` filters.

---

## License

```
GPL3
```
