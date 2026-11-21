"""SQLite storage for connection history, alerts and the baseline."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts REAL, kind TEXT, app TEXT, process TEXT, pid INTEGER,
  proto TEXT, local_port INTEGER, remote_ip TEXT, remote_port INTEGER, hostname TEXT,
  country_code TEXT, country TEXT, city TEXT, org TEXT, scope TEXT,
  bytes_in INTEGER, bytes_out INTEGER, duration REAL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, ts REAL, rule_id TEXT, rule_name TEXT, severity TEXT,
  app TEXT, process TEXT, remote_ip TEXT, remote_port INTEGER, hostname TEXT,
  country_code TEXT, org TEXT, details TEXT, acked INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS baseline (
  app TEXT, dest TEXT, first_seen REAL, PRIMARY KEY (app, dest)
);
"""

EVENT_COLS = ["ts", "kind", "app", "process", "pid", "proto", "local_port", "remote_ip",
              "remote_port", "hostname", "country_code", "country", "city", "org", "scope",
              "bytes_in", "bytes_out", "duration"]
ALERT_COLS = ["id", "ts", "rule_id", "rule_name", "severity", "app", "process", "remote_ip",
              "remote_port", "hostname", "country_code", "org", "details", "acked"]


class Store:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.lock = threading.Lock()

    # events
    def add_events(self, rows: list[dict]) -> None:
        if not rows:
            return
        q = f"INSERT INTO events ({','.join(EVENT_COLS)}) VALUES ({','.join('?' * len(EVENT_COLS))})"
        with self.lock, self.db:
            self.db.executemany(q, [[r.get(c) for c in EVENT_COLS] for r in rows])

    def search_events(self, text: str = "", kind: str = "", since: float = 0,
                      limit: int = 500) -> list[dict]:
        where, args = ["ts >= ?"], [since]
        if kind in ("open", "close"):
            where.append("kind = ?")
            args.append(kind)
        if text:
            like = f"%{text}%"
            where.append("(app LIKE ? OR process LIKE ? OR remote_ip LIKE ? OR hostname LIKE ?"
                         " OR org LIKE ? OR country LIKE ? OR country_code = ?)")
            args += [like] * 6 + [text.upper()]
        q = (f"SELECT {','.join(EVENT_COLS)} FROM events WHERE {' AND '.join(where)} "
             f"ORDER BY ts DESC LIMIT ?")
        with self.lock:
            cur = self.db.execute(q, args + [max(1, min(int(limit), 5000))])
            return [dict(zip(EVENT_COLS, r)) for r in cur.fetchall()]

    def top_history(self, since: float) -> dict:
        with self.lock:
            apps = self.db.execute(
                "SELECT app, COUNT(*), SUM(bytes_in), SUM(bytes_out) FROM events "
                "WHERE kind='close' AND ts>=? GROUP BY app ORDER BY SUM(bytes_in)+SUM(bytes_out) DESC LIMIT 15",
                (since,)).fetchall()
            countries = self.db.execute(
                "SELECT country_code, country, COUNT(*), SUM(bytes_in)+SUM(bytes_out) FROM events "
                "WHERE kind='close' AND ts>=? AND country_code!='' GROUP BY country_code "
                "ORDER BY 4 DESC LIMIT 30", (since,)).fetchall()
        return {
            "apps": [{"app": a, "conns": n, "bytes_in": bi or 0, "bytes_out": bo or 0}
                     for a, n, bi, bo in apps],
            "countries": [{"cc": c, "country": n, "conns": k, "bytes": b or 0}
                          for c, n, k, b in countries],
        }

    # alerts
    def add_alert(self, a: dict) -> int:
        cols = ALERT_COLS[1:-1]
        with self.lock, self.db:
            cur = self.db.execute(
                f"INSERT INTO alerts ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                [json.dumps(a[c]) if c == "details" else a.get(c) for c in cols])
            return cur.lastrowid

    def alerts(self, limit: int = 200, include_acked: bool = True) -> list[dict]:
        q = f"SELECT {','.join(ALERT_COLS)} FROM alerts"
        if not include_acked:
            q += " WHERE acked=0"
        q += " ORDER BY ts DESC LIMIT ?"
        with self.lock:
            rows = self.db.execute(q, (max(1, min(int(limit), 5000)),)).fetchall()
        out = []
        for r in rows:
            d = dict(zip(ALERT_COLS, r))
            try:
                d["details"] = json.loads(d["details"] or "{}")
            except ValueError:
                d["details"] = {}
            out.append(d)
        return out

    def unacked_counts(self) -> dict:
        with self.lock:
            rows = self.db.execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE acked=0 GROUP BY severity").fetchall()
        return dict(rows)

    def ack(self, ids: list[int] | None) -> int:
        with self.lock, self.db:
            if ids is None:
                return self.db.execute("UPDATE alerts SET acked=1 WHERE acked=0").rowcount
            ids = [int(i) for i in ids][:5000]
            if not ids:
                return 0
            return self.db.execute(
                f"UPDATE alerts SET acked=1 WHERE id IN ({','.join('?' * len(ids))})", ids).rowcount

    # baseline
    def load_baseline(self) -> set[tuple[str, str]]:
        with self.lock:
            return set(self.db.execute("SELECT app, dest FROM baseline").fetchall())

    def first_baseline_ts(self) -> float | None:
        with self.lock:
            return self.db.execute("SELECT MIN(first_seen) FROM baseline").fetchone()[0]

    def add_baseline(self, pairs: list[tuple[str, str]]) -> None:
        if pairs:
            now = time.time()
            with self.lock, self.db:
                self.db.executemany("INSERT OR IGNORE INTO baseline VALUES (?,?,?)",
                                    [(a, d, now) for a, d in pairs])

    def prune(self, retention_days: float) -> None:
        cutoff = time.time() - retention_days * 86400
        with self.lock, self.db:
            self.db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self.db.execute("DELETE FROM alerts WHERE ts < ? AND acked=1", (cutoff,))
