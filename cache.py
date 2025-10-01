# cache.py
import sqlite3, time, threading
from contextlib import contextmanager, closing
from typing import Iterable, List, Tuple
import asyncio


# Cache policy
MAX_CACHE_TTL = 300          # seconds to cap stored TTLs (5 min)
STALE_GRACE   = 30           # serve up to +30s stale while background refresh happens

# DB path (bind-mount this dir in Docker if you want persistence)
DB_PATH = "data/npubcache.sqlite3"

_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS rr_cache (
    fqdn        TEXT NOT NULL,
    rtype       TEXT NOT NULL,
    value       TEXT NOT NULL,
    ttl         INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    inserted_at INTEGER NOT NULL,
    PRIMARY KEY (fqdn, rtype, value)
);
CREATE INDEX IF NOT EXISTS idx_rr_cache_lookup ON rr_cache (fqdn, rtype, expires_at);
"""

@contextmanager
def _conn():
    con = sqlite3.connect(DB_PATH, timeout=2.0, isolation_level=None)  # autocommit
    try:
        yield con
    finally:
        con.close()

def init_cache():
    with _conn() as con:
        con.executescript(_SCHEMA)

def _now() -> int:
    return int(time.time())

def put_records(fqdn: str, records: Iterable[Tuple[str, str, int]]):
    """
    records: iterable of (rtype, value, ttl). We cap ttl by MAX_CACHE_TTL.
    """
    now = _now()
    rows = []
    for rtype, value, ttl in records:
        ttl_capped = min(int(ttl), MAX_CACHE_TTL)
        exp = now + ttl_capped
        rows.append((fqdn, rtype.upper(), str(value), ttl_capped, exp, now))
    if not rows:
        return
    with _conn() as con:
        con.executemany(
            "INSERT OR REPLACE INTO rr_cache (fqdn, rtype, value, ttl, expires_at, inserted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)", rows
        )

def get_records(fqdn: str, rtype: str) -> List[Tuple[str, str, int]]:
    """
    Return fresh or grace-stale records for (fqdn, rtype).
    Prefers fresh; if none, allows stale within STALE_GRACE.
    """
    now = _now()
    hi = now + STALE_GRACE
    with _conn() as con:
        # try fresh first
        cur = con.execute(
            "SELECT rtype, value, ttl FROM rr_cache WHERE fqdn=? AND rtype=? AND expires_at >= ?",
            (fqdn, rtype.upper(), now)
        )
        recs = cur.fetchall()
        if recs:
            return [(t, v, int(ttl)) for (t, v, ttl) in recs]

        # allow grace-stale
        cur = con.execute(
            "SELECT rtype, value, ttl FROM rr_cache WHERE fqdn=? AND rtype=? AND expires_at BETWEEN ? AND ?",
            (fqdn, rtype.upper(), now-3600, hi)  # avoid absurdly old rows
        )
        recs = cur.fetchall()
        if recs:
            return [(t, v, int(ttl)) for (t, v, ttl) in recs]

    return []

def purge_expired(limit: int = 500):
    with _conn() as con:
        con.execute("DELETE FROM rr_cache WHERE expires_at < ?", (_now()-3600,))

