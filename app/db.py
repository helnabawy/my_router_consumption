"""SQLite storage. One file, survives restarts, safe to copy as a backup.

Usage is stored in hourly buckets (UTC hour start as epoch seconds), which is
small (a year of 20 devices is ~175k rows) and lets us build hourly, daily
and monthly views with plain SUMs.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    key          TEXT PRIMARY KEY,       -- MAC address, or 'seg:<name>' for a router port / Wi-Fi network
    kind         TEXT NOT NULL DEFAULT 'device',   -- device | segment
    ip           TEXT,
    hostname     TEXT,
    vendor       TEXT,
    custom_name  TEXT,
    conn_type    TEXT,                   -- wifi | lan | NULL (unknown)
    segment      TEXT,                   -- which port / SSID the device is on, if the router says
    randomized   INTEGER NOT NULL DEFAULT 0,   -- private (randomized) MAC address
    is_gateway   INTEGER NOT NULL DEFAULT 0,
    is_self      INTEGER NOT NULL DEFAULT 0,   -- the computer running this app
    known        INTEGER NOT NULL DEFAULT 0,   -- you marked it as trusted
    daily_limit_mb INTEGER,
    first_seen   INTEGER,
    last_seen    INTEGER,
    sources      TEXT                    -- which collectors have seen it
);
CREATE TABLE IF NOT EXISTS counters (     -- last raw cumulative reading per source+key
    source TEXT NOT NULL, key TEXT NOT NULL,
    rx INTEGER, tx INTEGER, ts REAL,
    PRIMARY KEY (source, key)
);
CREATE TABLE IF NOT EXISTS usage_hourly (
    hour   INTEGER NOT NULL,              -- epoch seconds of the hour start (UTC)
    key    TEXT NOT NULL,                 -- device key, segment key or 'total'
    rx     INTEGER NOT NULL DEFAULT 0,    -- download (bytes delivered to the device)
    tx     INTEGER NOT NULL DEFAULT 0,    -- upload
    source TEXT,
    PRIMARY KEY (hour, key)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS presence_hourly (
    hour INTEGER NOT NULL, key TEXT NOT NULL,   -- key '__up__' = time the app itself was running
    seconds REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (hour, key)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL,
    key TEXT, message TEXT NOT NULL,
    dedupe TEXT UNIQUE,                   -- prevents the same alert firing twice
    acked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS we_readings (  -- usage figures you copy from the My WE app / my.te.eg
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL, used_gb REAL NOT NULL, note TEXT
);
CREATE INDEX IF NOT EXISTS idx_usage_key ON usage_hourly (key, hour);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts);
"""

DEVICE_EDITABLE = {"custom_name", "known", "daily_limit_mb"}


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)

    # ---- low level -----------------------------------------------------
    def execute(self, sql: str, params: Iterable = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, tuple(params))

    def query(self, sql: str, params: Iterable = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, tuple(params)).fetchall()]

    def transaction(self):
        return _Tx(self)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- settings ------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        rows = self.query("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def set_setting(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )

    # ---- devices -------------------------------------------------------
    def get_device(self, key: str) -> dict | None:
        rows = self.query("SELECT * FROM devices WHERE key=?", (key,))
        return rows[0] if rows else None

    def list_devices(self, kind: str | None = None) -> list[dict]:
        if kind:
            return self.query("SELECT * FROM devices WHERE kind=? ORDER BY first_seen", (kind,))
        return self.query("SELECT * FROM devices ORDER BY first_seen")

    def upsert_device(self, key: str, fields: dict, seen: bool, source: str,
                      now: int | None = None) -> bool:
        """Insert or update a device. Returns True if it is brand new.

        Empty values never overwrite existing information (a collector that
        does not know the hostname must not erase one another collector found).
        """
        now = now or int(time.time())
        fields = {k: v for k, v in fields.items() if v not in (None, "")}
        with self._lock:
            existing = self.get_device(key)
            if existing is None:
                cols = {"key": key, "first_seen": now, "sources": source,
                        "last_seen": now if seen else None, **fields}
                self._conn.execute(
                    f"INSERT INTO devices ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                    tuple(cols.values()),
                )
                return True
            sources = set(filter(None, (existing["sources"] or "").split(",")))
            sources.add(source)
            fields["sources"] = ",".join(sorted(sources))
            if seen:
                fields["last_seen"] = now
            sets = ",".join(f"{c}=?" for c in fields)
            self._conn.execute(f"UPDATE devices SET {sets} WHERE key=?", (*fields.values(), key))
            return False

    def edit_device(self, key: str, changes: dict) -> bool:
        changes = {k: v for k, v in changes.items() if k in DEVICE_EDITABLE}
        if not changes:
            return False
        sets = ",".join(f"{c}=?" for c in changes)
        cur = self.execute(f"UPDATE devices SET {sets} WHERE key=?", (*changes.values(), key))
        return cur.rowcount > 0

    def delete_device(self, key: str) -> None:
        with self.transaction():
            for table in ("devices", "usage_hourly", "presence_hourly", "counters"):
                self._conn.execute(f"DELETE FROM {table} WHERE key=?", (key,))

    # ---- counters ------------------------------------------------------
    def get_counter(self, source: str, key: str) -> dict | None:
        rows = self.query("SELECT rx,tx,ts FROM counters WHERE source=? AND key=?", (source, key))
        return rows[0] if rows else None

    def set_counter(self, source: str, key: str, rx: int, tx: int, ts: float) -> None:
        self.execute(
            "INSERT INTO counters(source,key,rx,tx,ts) VALUES(?,?,?,?,?) "
            "ON CONFLICT(source,key) DO UPDATE SET rx=excluded.rx, tx=excluded.tx, ts=excluded.ts",
            (source, key, rx, tx, ts),
        )

    # ---- usage ---------------------------------------------------------
    def add_usage(self, hour: int, key: str, rx: int, tx: int, source: str) -> None:
        self.execute(
            "INSERT INTO usage_hourly(hour,key,rx,tx,source) VALUES(?,?,?,?,?) "
            "ON CONFLICT(hour,key) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx, "
            "source=excluded.source",
            (hour, key, rx, tx, source),
        )

    def add_presence(self, hour: int, key: str, seconds: float) -> None:
        self.execute(
            "INSERT INTO presence_hourly(hour,key,seconds) VALUES(?,?,?) "
            "ON CONFLICT(hour,key) DO UPDATE SET seconds=seconds+excluded.seconds",
            (hour, key, seconds),
        )

    def usage_totals(self, start: int, end: int) -> dict[str, dict]:
        """{key: {'rx':..,'tx':..,'source':..}} summed over hours in [start, end)."""
        rows = self.query(
            "SELECT key, SUM(rx) AS rx, SUM(tx) AS tx, MAX(source) AS source "
            "FROM usage_hourly WHERE hour>=? AND hour<? GROUP BY key", (start, end))
        return {r["key"]: r for r in rows}

    def usage_rows(self, start: int, end: int, keys: list[str] | None = None) -> list[dict]:
        sql = "SELECT hour,key,rx,tx FROM usage_hourly WHERE hour>=? AND hour<?"
        params: list = [start, end]
        if keys is not None:
            if not keys:
                return []
            sql += f" AND key IN ({','.join('?' * len(keys))})"
            params += keys
        return self.query(sql + " ORDER BY hour", params)

    def first_usage_hour(self, key: str = "total") -> int | None:
        rows = self.query("SELECT MIN(hour) AS h FROM usage_hourly WHERE key=?", (key,))
        return rows[0]["h"] if rows else None

    # ---- alerts --------------------------------------------------------
    def add_alert(self, type_: str, severity: str, message: str, key: str | None = None,
                  dedupe: str | None = None, ts: int | None = None) -> bool:
        """Returns True if the alert is new (False if `dedupe` already fired)."""
        cur = self.execute(
            "INSERT OR IGNORE INTO alerts(ts,type,severity,key,message,dedupe) VALUES(?,?,?,?,?,?)",
            (ts or int(time.time()), type_, severity, key, message, dedupe),
        )
        return cur.rowcount > 0


class _Tx:
    """`with db.transaction():` groups many writes into one fast commit."""

    def __init__(self, db: Database):
        self.db = db

    def __enter__(self):
        self.db._lock.acquire()
        self.db._conn.execute("BEGIN")
        return self.db

    def __exit__(self, exc_type, exc, tb):
        try:
            self.db._conn.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self.db._lock.release()
        return False
