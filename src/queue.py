"""Crash-safe work queue. Claim with a lease so a killed worker retries."""
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

QUEUE_DB = "queues/queue.db"

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS queue (
  id          INTEGER PRIMARY KEY,
  url         TEXT UNIQUE NOT NULL,
  domain      TEXT NOT NULL,
  kind        TEXT NOT NULL DEFAULT 'product',
  status      TEXT NOT NULL DEFAULT 'pending',
  attempts    INTEGER NOT NULL DEFAULT 0,
  tier_used   INTEGER,
  lease_until TEXT,
  last_error  TEXT,
  created     TEXT NOT NULL,
  updated     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queue_claim ON queue(status, lease_until);
"""


def _now():
    return datetime.now(timezone.utc).isoformat()


class Queue:
    def __init__(self, path: str = QUEUE_DB):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.con = sqlite3.connect(path, timeout=30, isolation_level=None)
        self.con.row_factory = sqlite3.Row
        self.con.executescript(SCHEMA)

    def add(self, url: str, domain: str, kind: str = "product") -> bool:
        try:
            self.con.execute(
                "INSERT INTO queue (url, domain, kind, created, updated) "
                "VALUES (?,?,?,?,?)", (url, domain, kind, _now(), _now()))
            return True
        except sqlite3.IntegrityError:
            return False

    def add_many(self, rows) -> int:
        return sum(self.add(u, d, k) for u, d, k in rows)

    def claim(self, lease_s: int = 300, limit: int = 1):
        """Atomically claim up to `limit` pending or expired rows."""
        lease = (datetime.now(timezone.utc) + timedelta(seconds=lease_s)).isoformat()
        cur = self.con.execute("BEGIN IMMEDIATE")
        rows = self.con.execute(
            "SELECT id FROM queue WHERE status='pending' "
            "   OR (status='active' AND lease_until < ?) "
            "ORDER BY id LIMIT ?", (_now(), limit)).fetchall()
        for r in rows:
            self.con.execute(
                "UPDATE queue SET status='active', attempts=attempts+1, "
                "lease_until=?, updated=? WHERE id=?", (lease, _now(), r["id"]))
        self.con.execute("COMMIT")
        if not rows:
            return []
        ids = [r["id"] for r in rows]
        marks = ",".join("?" * len(ids))
        return self.con.execute(
            f"SELECT * FROM queue WHERE id IN ({marks})", ids).fetchall()

    def done(self, row_id: int, tier: int):
        self.con.execute(
            "UPDATE queue SET status='done', tier_used=?, lease_until=NULL, "
            "updated=? WHERE id=?", (tier, _now(), row_id))

    def fail(self, row_id: int, error: str, max_attempts: int = 3):
        status = "pending"
        row = self.con.execute("SELECT attempts FROM queue WHERE id=?",
                               (row_id,)).fetchone()
        if row and row["attempts"] >= max_attempts:
            status = "failed"
        self.con.execute(
            "UPDATE queue SET status=?, last_error=?, lease_until=NULL, "
            "updated=? WHERE id=?", (status, error[:500], _now(), row_id))

    def stats(self) -> dict:
        return {r["status"]: r["n"] for r in self.con.execute(
            "SELECT status, COUNT(*) n FROM queue GROUP BY status")}