"""SQLite persistence layer for the HookProof lab.

Business operation model
------------------------
* An ``orders`` row represents a synthetic order.
* A ``payments`` row represents one *protected business operation*: money was
  fulfilled for an event. Duplicate deliveries must therefore never create
  more than one ``payments`` row for a given ``event_id``.
* ``processed_events`` is the idempotency ledger. In secure mode it has a
  PRIMARY KEY constraint and is written inside an immediate transaction so
  concurrent deliveries cannot bypass it.

The vulnerable mode deliberately omits the idempotency guard.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA_COMMON = """
CREATE TABLE IF NOT EXISTS orders (
    order_id     TEXT PRIMARY KEY,
    amount_total INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS payments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id   TEXT NOT NULL,
    event_id   TEXT NOT NULL,
    amount     INTEGER NOT NULL,
    created_at REAL NOT NULL
);
"""

SCHEMA_VULNERABLE_EXTRA = """
CREATE TABLE IF NOT EXISTS processed_events (
    event_id     TEXT PRIMARY KEY,
    order_id     TEXT NOT NULL,
    processed_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_payments_order_vuln ON payments(order_id);
"""

SCHEMA_SECURE_EXTRA = """
CREATE TABLE IF NOT EXISTS processed_events (
    event_id     TEXT PRIMARY KEY,
    order_id     TEXT NOT NULL,
    processed_at REAL NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_payments_event_secure ON payments(event_id);
CREATE INDEX IF NOT EXISTS ix_payments_order_secure ON payments(order_id);
"""


class LabDB:
    """Thread-safe SQLite wrapper for one lab instance."""

    def __init__(self, path: str | Path, secure: bool) -> None:
        self.path = str(path)
        self.secure = secure
        self._lock = threading.Lock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)

    # -- connection helpers -------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA foreign_keys = ON")
        return con

    def init(self) -> None:
        """Create the schema for the configured mode."""
        with self._lock:
            con = self._connect()
            try:
                con.executescript(SCHEMA_COMMON)
                con.executescript(SCHEMA_SECURE_EXTRA if self.secure else SCHEMA_VULNERABLE_EXTRA)
            finally:
                con.close()

    def reset(self) -> None:
        """Delete all synthetic records."""
        with self._lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")
                con.execute("DELETE FROM payments")
                con.execute("DELETE FROM processed_events")
                con.execute("DELETE FROM orders")
                con.commit()
            finally:
                con.close()

    # -- business operation -------------------------------------------------
    def process_payment(self, event: dict[str, Any]) -> dict[str, Any]:
        """Apply the payment business operation for ``event``.

        Returns a dict with ``status`` (``processed``/``duplicate``) and
        ``duplicate`` boolean. The two modes implement this differently on
        purpose.
        """
        if self.secure:
            return self._process_secure(event)
        return self._process_vulnerable(event)

    def _process_vulnerable(self, event: dict[str, Any]) -> dict[str, Any]:
        order_id = event["order_id"]
        event_id = event["event_id"]
        amount = int(event["amount"])
        now = time.time()
        with self._lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")
                con.execute(
                    "INSERT OR IGNORE INTO orders(order_id, amount_total, status, created_at)"
                    " VALUES(?, 0, 'pending', ?)",
                    (order_id, now),
                )
                # Deliberately no idempotency guard: every delivery is applied.
                con.execute(
                    "INSERT INTO payments(order_id, event_id, amount, created_at) VALUES(?, ?, ?, ?)",
                    (order_id, event_id, amount, now),
                )
                con.execute(
                    "INSERT OR REPLACE INTO processed_events(event_id, order_id, processed_at)"
                    " VALUES(?, ?, ?)",
                    (event_id, order_id, now),
                )
                con.execute(
                    "UPDATE orders SET amount_total = amount_total + ?, status = 'paid' WHERE order_id = ?",
                    (amount, order_id),
                )
                con.commit()
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()
        return {"status": "processed", "duplicate": False}

    def _process_secure(self, event: dict[str, Any]) -> dict[str, Any]:
        order_id = event["order_id"]
        event_id = event["event_id"]
        amount = int(event["amount"])
        now = time.time()
        with self._lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")
                try:
                    con.execute(
                        "INSERT INTO processed_events(event_id, order_id, processed_at) VALUES(?, ?, ?)",
                        (event_id, order_id, now),
                    )
                except sqlite3.IntegrityError:
                    # Already processed: acknowledge safely, no side effects.
                    con.rollback()
                    return {"status": "duplicate", "duplicate": True}

                con.execute(
                    "INSERT OR IGNORE INTO orders(order_id, amount_total, status, created_at)"
                    " VALUES(?, 0, 'pending', ?)",
                    (order_id, now),
                )
                con.execute(
                    "INSERT INTO payments(order_id, event_id, amount, created_at) VALUES(?, ?, ?, ?)",
                    (order_id, event_id, amount, now),
                )
                con.execute(
                    "UPDATE orders SET amount_total = amount_total + ?, status = 'paid' WHERE order_id = ?",
                    (amount, order_id),
                )
                con.commit()
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()
        return {"status": "processed", "duplicate": False}

    # -- state inspection ---------------------------------------------------
    def get_order_state(self, order_id: str) -> dict[str, Any]:
        """Return the synthetic state needed by EffectProof for one order."""
        con = self._connect()
        try:
            order = con.execute(
                "SELECT order_id, amount_total, status, created_at FROM orders WHERE order_id = ?",
                (order_id,),
            ).fetchone()
            payments = con.execute(
                "SELECT event_id, amount, created_at FROM payments WHERE order_id = ? ORDER BY id ASC",
                (order_id,),
            ).fetchall()
            processed = con.execute(
                "SELECT event_id FROM processed_events WHERE order_id = ?",
                (order_id,),
            ).fetchall()
        finally:
            con.close()

        amount_total = int(order["amount_total"]) if order else 0
        return {
            "found": order is not None,
            "order_id": order_id,
            "status": order["status"] if order else None,
            "amount_total": amount_total,
            "payment_count": len(payments),
            "payment_amounts": [int(p["amount"]) for p in payments],
            "processed_event_ids": [p["event_id"] for p in processed],
        }

    def snapshot(self) -> dict[str, Any]:
        """Return aggregate counts for the whole synthetic dataset."""
        con = self._connect()
        try:
            orders = con.execute("SELECT COUNT(*) AS c FROM orders").fetchone()["c"]
            payments = con.execute("SELECT COUNT(*) AS c FROM payments").fetchone()["c"]
            events = con.execute("SELECT COUNT(*) AS c FROM processed_events").fetchone()["c"]
            total = con.execute("SELECT COALESCE(SUM(amount), 0) AS s FROM payments").fetchone()["s"]
        finally:
            con.close()
        return {
            "orders": int(orders),
            "payments": int(payments),
            "events": int(events),
            "payments_amount_sum": int(total),
        }
