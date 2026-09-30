#!/usr/bin/env python3
# ============================================================
# Sentinel Engram — sync worker
# ============================================================
# Phases (run in the order given on the command line):
#   verdicts    Cyber Sentinel AI verdicts  -> Synapse (inet:fqdn, inet:dns:a/aaaa, cs.* tags)
#   dns         DNS resolutions seen at home -> Synapse (inet:fqdn .seen, inet:dns:a/aaaa, #cs.seen)
#   blocklists  Pi-hole adlists              -> Synapse (#rep.blocklist.<slug>), incremental + resumable
#   project     Synapse                      -> Neo4j read-model (visualization)
#   all         verdicts dns project blocklists project
#
# Security model:
#   - Every Storm query is a constant string. Values from Cyber
#     Sentinel / blocklists (attacker-controlled domain names) travel
#     ONLY through opts.vars — never concatenated into Storm text.
#     The only dynamic part of a query is the NUMBER of tag
#     placeholders ($t0, $t1, ...), generated from an integer.
#   - Try-operators (?=) make Synapse skip values that fail type
#     normalization instead of aborting the whole batch.
#   - Postgres access is read-only (engram_reader role) over an SSH
#     tunnel that exists only while this process runs.
#
# State (SQLite, /state/engram_state.db):
#   kv          watermarks (verdicts, dns)
#   bl_lists    per-list sha256 + last fetch time
#   bl_domains  last ingested domain set per list (for diffs)
#   bl_pending  queued add/del operations — committed per batch, so a
#               shutdown mid-ingest resumes where it stopped
# ============================================================

import argparse
import contextlib
import datetime as dt
import decimal
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse

import psycopg
import requests
import urllib3
from neo4j import GraphDatabase
from psycopg.rows import dict_row

# ------------------------------------------------------------
# Configuration (environment, set by docker compose / .env)
# ------------------------------------------------------------
ENV = os.environ

CORTEX_URL = ENV.get("CORTEX_URL", "https://engram-cortex:4443")
CORTEX_USER = ENV.get("SYNAPSE_SYNC_USER", "engram-sync")
CORTEX_PASS = ENV.get("SYNAPSE_SYNC_PASSWORD", "")

NEO4J_URI = ENV.get("NEO4J_URI", "bolt://engram-neo4j:7687")
NEO4J_PASS = ENV.get("NEO4J_PASSWORD", "")

CS_SSH_HOST = ENV.get("CS_SSH_HOST", "")
CS_SSH_USER = ENV.get("CS_SSH_USER", "engram-tunnel")
CS_PG_TARGET = ENV.get("CS_PG_TARGET", "10.10.10.9:5432")
CS_PG_DATABASE = ENV.get("CS_PG_DATABASE", "cyber_intelligence")
CS_PG_USER = ENV.get("CS_PG_USER", "engram_reader")
CS_PG_PASSWORD = ENV.get("CS_PG_PASSWORD", "")
TUNNEL_KEY = ENV.get("TUNNEL_KEY", "/secrets/cs_tunnel_key")
TUNNEL_LOCAL_PORT = int(ENV.get("TUNNEL_LOCAL_PORT", "15432"))

STATE_DIR = ENV.get("STATE_DIR", "/state")
BLOCKLIST_FILE = ENV.get("BLOCKLIST_FILE", "/config/blocklists.txt")

VERDICT_OVERLAP_HOURS = int(ENV.get("VERDICT_OVERLAP_HOURS", "24"))
DNS_OVERLAP_DAYS = int(ENV.get("DNS_OVERLAP_DAYS", "1"))
DNS_INITIAL_DAYS = int(ENV.get("DNS_INITIAL_DAYS", "190"))  # > Cyber Sentinel's 6-month retention
DNS_BATCH = int(ENV.get("DNS_BATCH", "1000"))

BLOCKLIST_MAX_MINUTES = int(ENV.get("BLOCKLIST_MAX_MINUTES", "90"))
BLOCKLIST_BATCH = int(ENV.get("BLOCKLIST_BATCH", "2000"))
BLOCKLIST_LIMIT = int(ENV.get("BLOCKLIST_LIMIT", "0"))
BLOCKLIST_REFRESH_HOURS = int(ENV.get("BLOCKLIST_REFRESH_HOURS", "24"))
BLOCKLIST_MAX_BYTES = int(ENV.get("BLOCKLIST_MAX_BYTES", str(300 * 1024 * 1024)))
BLOCKLIST_SHRINK_GUARD = float(ENV.get("BLOCKLIST_SHRINK_GUARD", "0.5"))

NEO4J_MAX_NODES = int(ENV.get("NEO4J_MAX_NODES", "20000"))

HTTP_TIMEOUT = (10, 600)  # (connect, read) seconds

log = logging.getLogger("engram-sync")

# The Cortex certificate is self-signed and the hop never leaves the
# internal Docker network — verification is disabled for this hop only.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SyncError(Exception):
    pass


# ============================================================
# Helpers
# ============================================================

TAG_PART_RE = re.compile(r"[^a-z0-9_]+")


def tag_part(value):
    """Normalize a free-text value into one Synapse tag segment."""
    part = TAG_PART_RE.sub("_", str(value).strip().lower()).strip("_")
    return part[:64] or "unknown"


def to_ms(value):
    """datetime (naive = UTC) -> epoch milliseconds, as Synapse time values."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return int(value.timestamp() * 1000)


def ip_kind(value):
    """Return (normalized_ip, 4|6) or (None, None) for non-IP strings."""
    if not value:
        return None, None
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None, None
    return str(ip), ip.version


def jsonable(value):
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    return value


# ============================================================
# Synapse Cortex HTTP client
# ============================================================

class Cortex:
    def __init__(self, url, user, passwd):
        self.url = url.rstrip("/")
        self.sess = requests.Session()
        self.sess.auth = (user, passwd)
        self.sess.verify = False
        # Without this, REQUESTS_CA_BUNDLE / HTTPS_PROXY from the
        # environment override verify=False and would route an
        # internal-network call through a proxy.
        self.sess.trust_env = False

    def call(self, query, vars_=None):
        """/api/v1/storm/call — run a query, return its return() value."""
        body = {"query": query, "opts": {"vars": vars_ or {}}}
        resp = self.sess.get(f"{self.url}/api/v1/storm/call", json=body, timeout=HTTP_TIMEOUT)
        try:
            data = resp.json()
        except ValueError as exc:
            raise SyncError(f"Cortex returned non-JSON (HTTP {resp.status_code})") from exc
        if data.get("status") != "ok":
            raise SyncError(f"Storm error {data.get('code')}: {data.get('mesg')}")
        return data.get("result")

    def nodes(self, query, vars_=None):
        """/api/v1/storm (jsonlines stream) — yield (ndef, info) per node, read-only."""
        body = {
            "query": query,
            "opts": {"vars": vars_ or {}, "repr": True, "readonly": True},
            "stream": "jsonlines",
        }
        with self.sess.get(f"{self.url}/api/v1/storm", json=body, stream=True, timeout=HTTP_TIMEOUT) as resp:
            if resp.status_code != 200:
                raise SyncError(f"Cortex /storm HTTP {resp.status_code}")
            for line in resp.iter_lines():
                if not line:
                    continue
                mtyp, info = json.loads(line)
                if mtyp == "node":
                    yield info[0], info[1]
                elif mtyp == "err":
                    raise SyncError(f"Storm error {info[0]}: {info[1].get('mesg')}")

    def ping(self):
        who = self.call("return($lib.user.name())")
        if who != CORTEX_USER:
            raise SyncError(f"Authenticated as {who!r}, expected {CORTEX_USER!r}")


# ============================================================
# SSH tunnel to Cyber Sentinel Postgres
# ============================================================

class PgTunnel(contextlib.AbstractContextManager):
    """ssh -N -L 127.0.0.1:<port>:<postgres_db ip>:5432 — lives for one run."""

    def __init__(self):
        self.proc = None

    def __enter__(self):
        if not CS_SSH_HOST:
            raise SyncError("CS_SSH_HOST is not set")
        known_hosts = os.path.join(STATE_DIR, "known_hosts")
        cmd = [
            "ssh", "-N",
            "-i", TUNNEL_KEY,
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", "ExitOnForwardFailure=yes",
            # Trust-on-first-use, persisted in the state volume: the
            # Pi's host key is pinned after the first successful run.
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-L", f"127.0.0.1:{TUNNEL_LOCAL_PORT}:{CS_PG_TARGET}",
            f"{CS_SSH_USER}@{CS_SSH_HOST}",
        ]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise SyncError(f"SSH tunnel exited: {self.proc.stderr.read().strip()}")
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", TUNNEL_LOCAL_PORT), timeout=1):
                log.info("tunnel up -> %s@%s (%s)", CS_SSH_USER, CS_SSH_HOST, CS_PG_TARGET)
                return self
            time.sleep(0.5)
        self.__exit__(None, None, None)
        raise SyncError("SSH tunnel did not open within 20s")

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.proc.wait(timeout=5)
            if self.proc.poll() is None:
                self.proc.kill()
        return False

    @staticmethod
    def connect():
        return psycopg.connect(
            host="127.0.0.1",
            port=TUNNEL_LOCAL_PORT,
            dbname=CS_PG_DATABASE,
            user=CS_PG_USER,
            password=CS_PG_PASSWORD,
            connect_timeout=10,
            application_name="sentinel-engram-sync",
        )


# ============================================================
# Local state
# ============================================================

class State:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS bl_lists (
                slug TEXT PRIMARY KEY, url TEXT, sha256 TEXT,
                domains INTEGER, fetched_at INTEGER);
            CREATE TABLE IF NOT EXISTS bl_domains (
                slug TEXT, fqdn TEXT, PRIMARY KEY (slug, fqdn)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS bl_pending (
                slug TEXT, fqdn TEXT, op TEXT, PRIMARY KEY (slug, fqdn)) WITHOUT ROWID;
            """
        )
        self.db.commit()

    def get(self, key, default=None):
        row = self.db.execute("SELECT v FROM kv WHERE k = ?", (key,)).fetchone()
        return row[0] if row else default

    def set(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", (key, str(value)))
        self.db.commit()


# ============================================================
# Phase: verdicts
# ============================================================

VERDICT_SQL = """
SELECT indicator_id, last_scan, scan_count, fqdn, record_type, observable_ip,
       analysis_id, threat_score, threat_label, threat_level, is_malicious,
       confidence_score, analyzed_at, providers
FROM engram_export.v_verdicts
WHERE last_scan > %s
ORDER BY last_scan, indicator_id
"""

STORM_DNS_A = "[ inet:dns:a?=($fqdn, $ip) .seen?=$seen +#cs.verdict ]"
STORM_DNS_AAAA = "[ inet:dns:aaaa?=($fqdn, $ip) .seen?=$seen +#cs.verdict ]"


def storm_verdict_fqdn(tag_count):
    # Only the placeholder COUNT varies; tag values arrive via $t0..$tN.
    tags = " ".join(f"+#$t{i}" for i in range(tag_count))
    return (
        f"[ inet:fqdn?=$fqdn .seen?=$seen {tags} ]\n"
        "$node.data.set(\"cs_verdict\", $data)"
    )


def verdict_tags(row):
    tags = ["cs.verdict", f"cs.score.{int(row['threat_score'])}"]
    if row["is_malicious"]:
        tags.append("cs.malicious")
    for provider in row["providers"] or []:
        tags.append(f"cs.src.{tag_part(provider)}")
    return tags


def phase_verdicts(cortex, state, pg):
    since = state.get("verdict_last_scan", "1970-01-01T00:00:00")
    since_dt = dt.datetime.fromisoformat(since) - dt.timedelta(hours=VERDICT_OVERLAP_HOURS)
    done = failed = 0
    newest = dt.datetime.fromisoformat(since)

    with pg.cursor(row_factory=dict_row) as cur:
        cur.execute(VERDICT_SQL, (since_dt,))
        for row in cur:
            seen_ms = to_ms(row["last_scan"])
            tags = verdict_tags(row)
            data = {k: jsonable(row[k]) for k in (
                "indicator_id", "analysis_id", "threat_score", "threat_label", "threat_level",
                "is_malicious", "confidence_score", "analyzed_at", "scan_count", "providers")}
            vars_ = {"fqdn": row["fqdn"], "seen": [seen_ms, seen_ms], "data": data}
            vars_.update({f"t{i}": t for i, t in enumerate(tags)})
            try:
                cortex.call(storm_verdict_fqdn(len(tags)), vars_)
                ip, ver = ip_kind(row["observable_ip"])
                if ip:
                    cortex.call(STORM_DNS_A if ver == 4 else STORM_DNS_AAAA,
                                {"fqdn": row["fqdn"], "ip": ip, "seen": [seen_ms, seen_ms]})
                done += 1
            except (SyncError, requests.RequestException) as exc:
                failed += 1
                log.warning("verdict indicator_id=%s failed: %s", row["indicator_id"], exc)
            newest = max(newest, row["last_scan"])

    state.set("verdict_last_scan", newest.isoformat())
    log.info("verdicts: %d ingested, %d failed, watermark=%s", done, failed, newest.isoformat())
    if failed and not done:
        raise SyncError("every verdict failed")


# ============================================================
# Phase: dns (resolutions seen on the home network)
# ============================================================

DNS_SQL = "SELECT fqdn, response_ip, first_seen, last_seen, hits FROM engram_export.fn_dns_seen(%s)"

STORM_DNS_FQDN = "for $r in $rows { [ inet:fqdn?=$r.fqdn .seen?=$r.seen +#cs.seen ] }"
STORM_DNS_A_BATCH = "for $r in $rows { [ inet:dns:a?=($r.fqdn, $r.ip) .seen?=$r.seen +#cs.seen ] }"
STORM_DNS_AAAA_BATCH = "for $r in $rows { [ inet:dns:aaaa?=($r.fqdn, $r.ip) .seen?=$r.seen +#cs.seen ] }"


def phase_dns(cortex, state, pg):
    default_since = (dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(days=DNS_INITIAL_DAYS)).isoformat()
    since = dt.datetime.fromisoformat(state.get("dns_last_seen", default_since))
    query_since = since - dt.timedelta(days=DNS_OVERLAP_DAYS)
    newest = since
    counts = {"fqdn": 0, "a": 0, "aaaa": 0}

    def flush(query, rows, key):
        if rows:
            cortex.call(query, {"rows": rows})
            counts[key] += len(rows)
            rows.clear()

    fqdns, a_rows, aaaa_rows = [], [], []
    with pg.cursor() as cur:
        cur.execute(DNS_SQL, (query_since,))
        for fqdn, resp_ip, first_seen, last_seen, _hits in cur:
            seen = [to_ms(first_seen), to_ms(last_seen)]
            fqdns.append({"fqdn": fqdn, "seen": seen})
            ip, ver = ip_kind(resp_ip)
            if ip:
                (a_rows if ver == 4 else aaaa_rows).append({"fqdn": fqdn, "ip": ip, "seen": seen})
            newest = max(newest, last_seen)
            if len(fqdns) >= DNS_BATCH:
                flush(STORM_DNS_FQDN, fqdns, "fqdn")
            if len(a_rows) >= DNS_BATCH:
                flush(STORM_DNS_A_BATCH, a_rows, "a")
            if len(aaaa_rows) >= DNS_BATCH:
                flush(STORM_DNS_AAAA_BATCH, aaaa_rows, "aaaa")
    flush(STORM_DNS_FQDN, fqdns, "fqdn")
    flush(STORM_DNS_A_BATCH, a_rows, "a")
    flush(STORM_DNS_AAAA_BATCH, aaaa_rows, "aaaa")

    state.set("dns_last_seen", newest.isoformat())
    log.info("dns: %d fqdn, %d A, %d AAAA, watermark=%s",
             counts["fqdn"], counts["a"], counts["aaaa"], newest.isoformat())


# ============================================================
# Phase: blocklists
# ============================================================

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$"
)
SKIP_HOSTS = {"localhost", "localhost.localdomain", "local", "broadcasthost",
              "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
              "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"}

STORM_BL_ADD = "for $f in $fqdns { [ inet:fqdn?=$f +#$tag ] }"
# Synapse keeps parent tags (rep, rep.blocklist) when a leaf tag is
# removed. Without the cleanup, a domain dropped from its last list
# would still match `+#rep.blocklist` in the Neo4j projection.
STORM_BL_DEL = """for $f in $fqdns {
    inet:fqdn?=$f [ -#$tag ]
    if (not $node.globtags("rep.blocklist.*")) { [ -#rep.blocklist ] }
    if (not $node.globtags("rep.*")) { [ -#rep ] }
}"""


def normalize_url(url):
    """github.com/<o>/<r>/blob/<ref>/<path> serves an HTML page, not the list."""
    u = urllib.parse.urlparse(url)
    parts = [p for p in u.path.split("/") if p]
    if u.netloc.lower() == "github.com" and len(parts) > 3 and parts[2] == "blob":
        raw = f"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/{'/'.join(parts[3:])}"
        log.warning("blob URL rewritten to raw: %s -> %s (Pi-hole receives an HTML page from the original URL)",
                    url, raw)
        return raw
    return url


def list_slug(url):
    u = urllib.parse.urlparse(url)
    host = u.netloc.lower().removeprefix("www.")
    parts = [p for p in u.path.split("/") if p]
    stem = re.sub(r"\.(txt|hosts|list|php|csv)$", "", parts[-1]) if parts else ""
    if host in ("raw.githubusercontent.com", "github.com", "gitlab.com", "bitbucket.org") and len(parts) >= 2:
        base = f"{parts[0]}_{parts[1]}_{stem}"
    else:
        base = f"{host.rsplit('.', 1)[0]}_{stem}"
    return tag_part(base)[:60]


def load_sources():
    sources, used = [], set()
    with open(BLOCKLIST_FILE, encoding="utf-8") as fh:
        for line in fh:
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            slug = list_slug(url)
            n = 2
            while slug in used:
                slug = f"{list_slug(url)}_{n}"
                n += 1
            used.add(slug)
            sources.append((slug, url))
    if BLOCKLIST_LIMIT > 0:
        sources = sources[:BLOCKLIST_LIMIT]
    return sources


def parse_line(line):
    """Yield domains from one hosts / plain / adblock-style line."""
    line = line.split("#", 1)[0].strip().lower()
    if not line or line.startswith(("!", "[")):
        return
    if line.startswith("||"):
        line = line[2:].split("^", 1)[0].split("$", 1)[0]
        tokens = [line]
    else:
        tokens = line.split()
        if len(tokens) > 1:
            try:
                ipaddress.ip_address(tokens[0])
                tokens = tokens[1:]
            except ValueError:
                return  # not a hosts line and not a single domain
    for tok in tokens:
        dom = tok.strip(".")
        if not dom or "*" in dom or dom in SKIP_HOSTS:
            continue
        try:
            ipaddress.ip_address(dom)
            continue
        except ValueError:
            pass
        if not dom.isascii():
            try:
                dom = dom.encode("idna").decode("ascii")
            except UnicodeError:
                continue
        if DOMAIN_RE.match(dom):
            yield dom


def fetch_list(url, dest):
    sha = hashlib.sha256()
    size = 0
    with requests.get(url, stream=True, timeout=(10, 120),
                      headers={"User-Agent": "sentinel-engram-sync"}) as resp:
        resp.raise_for_status()
        for chunk in resp.iter_content(chunk_size=1 << 16):
            size += len(chunk)
            if size > BLOCKLIST_MAX_BYTES:
                raise SyncError(f"list exceeds {BLOCKLIST_MAX_BYTES} bytes")
            sha.update(chunk)
            dest.write(chunk)
    dest.flush()
    return sha.hexdigest()


def refresh_list(state, slug, url):
    """Download, diff against the last ingested set, queue add/del ops."""
    row = state.db.execute("SELECT sha256, fetched_at FROM bl_lists WHERE slug = ?", (slug,)).fetchone()
    now = int(time.time())
    if row and row[1] and now - row[1] < BLOCKLIST_REFRESH_HOURS * 3600:
        return "fresh"

    fetch_url = normalize_url(url)
    with tempfile.NamedTemporaryFile(dir=STATE_DIR, prefix="bl_", suffix=".tmp") as tmp:
        digest = fetch_list(fetch_url, tmp)
        if row and row[0] == digest:
            state.db.execute("UPDATE bl_lists SET fetched_at = ? WHERE slug = ?", (now, slug))
            state.db.commit()
            return "unchanged"

        tmp.seek(0)
        head = tmp.read(512).lstrip().lower()
        if head.startswith((b"<!doctype html", b"<html")):
            raise SyncError("server returned an HTML page, not a list")

        db = state.db
        db.execute("CREATE TEMP TABLE IF NOT EXISTS bl_new (fqdn TEXT PRIMARY KEY) WITHOUT ROWID")
        db.execute("DELETE FROM bl_new")
        tmp.seek(0)
        batch = []
        for raw in tmp:
            batch.extend(parse_line(raw.decode("utf-8", errors="ignore")))
            if len(batch) >= 50000:
                db.executemany("INSERT OR IGNORE INTO bl_new VALUES (?)", ((d,) for d in batch))
                batch.clear()
        db.executemany("INSERT OR IGNORE INTO bl_new VALUES (?)", ((d,) for d in batch))

        total = db.execute("SELECT count(*) FROM bl_new").fetchone()[0]
        # Guard: an empty or truncated download (HTTP 200 with an error
        # body, mirror hiccup) would otherwise queue a `del` for every
        # domain on the list. A real list shrinking by more than half
        # in one refresh is rare enough to require a manual look.
        previous = db.execute("SELECT domains FROM bl_lists WHERE slug = ?", (slug,)).fetchone()
        if total == 0 or (previous and previous[0] and total < previous[0] * BLOCKLIST_SHRINK_GUARD):
            raise SyncError(f"refusing update: {total} domains now vs {previous[0] if previous else 0} before")
        # INSERT OR REPLACE: the latest operation for a domain wins if an
        # older queued op for the same domain has not been pushed yet.
        db.execute(
            "INSERT OR REPLACE INTO bl_pending (slug, fqdn, op) "
            "SELECT ?, fqdn, 'add' FROM (SELECT fqdn FROM bl_new "
            "EXCEPT SELECT fqdn FROM bl_domains WHERE slug = ?)", (slug, slug))
        db.execute(
            "INSERT OR REPLACE INTO bl_pending (slug, fqdn, op) "
            "SELECT ?, fqdn, 'del' FROM (SELECT fqdn FROM bl_domains WHERE slug = ? "
            "EXCEPT SELECT fqdn FROM bl_new)", (slug, slug))
        db.execute("DELETE FROM bl_domains WHERE slug = ?", (slug,))
        db.execute("INSERT INTO bl_domains (slug, fqdn) SELECT ?, fqdn FROM bl_new", (slug,))
        db.execute(
            "INSERT OR REPLACE INTO bl_lists (slug, url, sha256, domains, fetched_at) VALUES (?, ?, ?, ?, ?)",
            (slug, url, digest, total, now))
        db.commit()
        return f"changed ({total} domains)"


def push_pending(cortex, state, deadline):
    db = state.db
    pushed = 0
    while time.monotonic() < deadline:
        head = db.execute("SELECT slug, op FROM bl_pending LIMIT 1").fetchone()
        if not head:
            return pushed, 0
        slug, op = head
        rows = [r[0] for r in db.execute(
            "SELECT fqdn FROM bl_pending WHERE slug = ? AND op = ? LIMIT ?", (slug, op, BLOCKLIST_BATCH))]
        cortex.call(STORM_BL_ADD if op == "add" else STORM_BL_DEL,
                    {"fqdns": rows, "tag": f"rep.blocklist.{slug}"})
        db.executemany("DELETE FROM bl_pending WHERE slug = ? AND fqdn = ?", ((slug, f) for f in rows))
        db.commit()
        pushed += len(rows)
    remaining = db.execute("SELECT count(*) FROM bl_pending").fetchone()[0]
    return pushed, remaining


def phase_blocklists(cortex, state):
    budget = BLOCKLIST_MAX_MINUTES * 60 if BLOCKLIST_MAX_MINUTES > 0 else 10 ** 9
    deadline = time.monotonic() + budget

    # 1. Finish work queued by an interrupted run before fetching more.
    pushed, remaining = push_pending(cortex, state, deadline)
    if remaining:
        log.info("blocklists: pushed %d queued ops, %d still queued (time budget)", pushed, remaining)
        return

    # 2. Refresh sources and queue diffs.
    for slug, url in load_sources():
        if time.monotonic() >= deadline:
            break
        try:
            result = refresh_list(state, slug, url)
            if result not in ("fresh", "unchanged"):
                log.info("blocklist %s: %s", slug, result)
        except (SyncError, requests.RequestException, OSError) as exc:
            log.warning("blocklist %s (%s) skipped: %s", slug, url, exc)

    # 3. Push what was queued.
    more, remaining = push_pending(cortex, state, deadline)
    log.info("blocklists: pushed %d ops, %d queued for next run", pushed + more, remaining)


# ============================================================
# Phase: project (Synapse -> Neo4j)
# ============================================================
# Scope: CTI-relevant subgraph only. The full blocklist set (millions
# of inet:fqdn) is intentionally NOT projected — Neo4j Browser cannot
# render it meaningfully and it would not fit the memory budget.
#   Q1 domains with an AI verdict
#   Q2 domains seen on the home network that ARE on a blocklist
#      (allowed through Pi-hole but listed — anomaly candidates)
#   Q3 resolutions of verdict domains
#   Q4 other resolutions pointing at the same IPs (shared infrastructure)
#   Q5 the neighbour domains from Q4, with their tags

PROJECTION_QUERIES = [
    ("fqdn", "inet:fqdn#cs.verdict | limit $max"),
    ("fqdn", "inet:fqdn#cs.seen +#rep.blocklist | limit $max"),
    ("dns", "inet:fqdn#cs.verdict -> inet:dns:a | limit $max"),
    ("dns", "inet:fqdn#cs.verdict -> inet:dns:aaaa | limit $max"),
    ("dns", "inet:fqdn#cs.verdict -> inet:dns:a -> inet:ipv4 -> inet:dns:a | limit $max"),
    ("fqdn", "inet:fqdn#cs.verdict -> inet:dns:a -> inet:ipv4 -> inet:dns:a -> inet:fqdn | limit $max"),
]


def domain_props(info):
    tags = info.get("tags", {})
    scores = [int(t.rsplit(".", 1)[1]) for t in tags if re.fullmatch(r"cs\.score\.\d", t)]
    seen = info.get("props", {}).get(".seen") or [None, None]
    return {
        "score": max(scores) if scores else None,
        "verdict": "cs.verdict" in tags,
        "malicious": "cs.malicious" in tags,
        "seen_home": "cs.seen" in tags,
        "first_seen": seen[0],
        "last_seen": seen[1],
        "ai_tags": sorted(t for t in tags if t.startswith("ai.")),
    }, {
        "lists": sorted(t.split(".", 2)[2] for t in tags if t.startswith("rep.blocklist.") and t.count(".") == 2),
        "sources": sorted(t.split(".", 2)[2] for t in tags if t.startswith("cs.src.") and t.count(".") == 2),
        "malware": sorted(t.split(".", 2)[2] for t in tags if t.startswith("cs.mal.") and t.count(".") == 2),
    }


CY_DOMAINS = """
UNWIND $rows AS r
MERGE (d:Domain {name: r.name})
SET d += r.props, d.projected_at = $run
WITH d, r
UNWIND r.lists AS slug
  MERGE (b:Blocklist {slug: slug}) SET b.projected_at = $run
  MERGE (d)-[l:LISTED_ON]->(b) SET l.projected_at = $run
"""
CY_SOURCES = """
UNWIND $rows AS r
MATCH (d:Domain {name: r.name})
UNWIND r.sources AS src
  MERGE (s:Source {name: src}) SET s.projected_at = $run
  MERGE (d)-[x:CHECKED_BY]->(s) SET x.projected_at = $run
"""
CY_MALWARE = """
UNWIND $rows AS r
MATCH (d:Domain {name: r.name})
UNWIND r.malware AS mal
  MERGE (m:MalwareFamily {name: mal}) SET m.projected_at = $run
  MERGE (d)-[x:ATTRIBUTED_TO]->(m) SET x.projected_at = $run
"""
CY_EDGES = """
UNWIND $rows AS e
MERGE (d:Domain {name: e.fqdn}) SET d.projected_at = $run
MERGE (i:IP {addr: e.ip}) SET i.version = e.version, i.projected_at = $run
MERGE (d)-[r:RESOLVES_TO]->(i)
SET r.first_seen = e.first_seen, r.last_seen = e.last_seen, r.projected_at = $run
"""
CY_CLEANUP = [
    "MATCH ()-[r]->() WHERE r.projected_at < $run DELETE r",
    "MATCH (n) WHERE (n:Domain OR n:IP) AND n.projected_at < $run DETACH DELETE n",
    "MATCH (n) WHERE (n:Blocklist OR n:Source OR n:MalwareFamily) AND NOT (n)--() DELETE n",
]


def phase_project(cortex):
    run = int(time.time() * 1000)
    domains, edges = {}, {}
    for kind, query in PROJECTION_QUERIES:
        for ndef, info in cortex.nodes(query, {"max": NEO4J_MAX_NODES}):
            form = ndef[0]
            if kind == "fqdn" and form == "inet:fqdn":
                props, rels = domain_props(info)
                domains[ndef[1]] = {"name": ndef[1], "props": props, **rels}
            elif form in ("inet:dns:a", "inet:dns:aaaa"):
                p = info.get("props", {})
                if form == "inet:dns:a":
                    ip = str(ipaddress.IPv4Address(int(p["ipv4"]))) if "ipv4" in p else None
                    version = 4
                else:
                    ip, version = p.get("ipv6"), 6
                if not ip or "fqdn" not in p:
                    continue
                seen = p.get(".seen") or [None, None]
                edges[(p["fqdn"], ip)] = {"fqdn": p["fqdn"], "ip": ip, "version": version,
                                          "first_seen": seen[0], "last_seen": seen[1]}

    driver = GraphDatabase.driver(NEO4J_URI, auth=("neo4j", NEO4J_PASS))
    try:
        rows = list(domains.values())
        for i in range(0, len(rows), 1000):
            chunk = rows[i:i + 1000]
            driver.execute_query(CY_DOMAINS, rows=chunk, run=run, database_="neo4j")
            driver.execute_query(CY_SOURCES, rows=chunk, run=run, database_="neo4j")
            driver.execute_query(CY_MALWARE, rows=chunk, run=run, database_="neo4j")
        erows = list(edges.values())
        for i in range(0, len(erows), 1000):
            driver.execute_query(CY_EDGES, rows=erows[i:i + 1000], run=run, database_="neo4j")
        for stmt in CY_CLEANUP:
            driver.execute_query(stmt, run=run, database_="neo4j")
    finally:
        driver.close()
    log.info("project: %d domains, %d resolutions -> Neo4j", len(domains), len(edges))


# ============================================================
# Main
# ============================================================

PHASES = ("verdicts", "dns", "blocklists", "project")


def main():
    parser = argparse.ArgumentParser(description="Sentinel Engram sync worker")
    parser.add_argument("phases", nargs="*", default=["all"], choices=PHASES + ("all",))
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    phases = []
    for p in args.phases:
        phases.extend(["verdicts", "dns", "project", "blocklists", "project"] if p == "all" else [p])

    state = State(os.path.join(STATE_DIR, "engram_state.db"))
    cortex = Cortex(CORTEX_URL, CORTEX_USER, CORTEX_PASS)
    cortex.ping()

    failures = []
    pg_phases = [p for p in phases if p in ("verdicts", "dns")]
    if pg_phases:
        try:
            with PgTunnel(), PgTunnel.connect() as pg:
                for phase in pg_phases:
                    try:
                        (phase_verdicts if phase == "verdicts" else phase_dns)(cortex, state, pg)
                    except (SyncError, psycopg.Error, requests.RequestException) as exc:
                        failures.append(phase)
                        log.error("%s failed: %s", phase, exc)
        except (SyncError, psycopg.Error, OSError) as exc:
            failures.extend(pg_phases)
            log.error("Cyber Sentinel source unavailable: %s", exc)

    for phase in phases:
        try:
            if phase == "blocklists":
                phase_blocklists(cortex, state)
            elif phase == "project":
                phase_project(cortex)
        except Exception as exc:  # noqa: BLE001 — report and continue with the next phase
            failures.append(phase)
            log.error("%s failed: %s", phase, exc)

    if failures:
        log.error("finished with failures: %s", sorted(set(failures)))
        return 1
    log.info("finished OK: %s", " ".join(phases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
