"""Seeded demo business data — a tiny CRM/orders world with fake records.

This is the system the agent acts on. Tools are the only way in; the agent
process holds no direct write path around the gateway.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

CUSTOMERS = [
    ("C-1001", "Priya Nair", "priya.nair@example.com", "gold"),
    ("C-1002", "Marcus Lee", "marcus.lee@example.com", "standard"),
    ("C-1003", "Ana Ribeiro", "ana.ribeiro@example.com", "gold"),
    ("C-1004", "Tom Becker", "tom.becker@example.com", "standard"),
]
ORDERS = [
    (8841, "C-1001", "Wireless headphones", 12999, "delivered"),
    (8842, "C-1002", "USB-C dock", 8900, "delivered"),
    (8843, "C-1001", "Laptop stand", 5900, "shipped"),
    (8844, "C-1003", "Mechanical keyboard", 15900, "delivered"),
    (8845, "C-1004", "Webcam", 7400, "processing"),
]
TICKETS = [
    (501, "C-1001", "Headphones arrived with a cracked ear cup", "normal", "open"),
    (502, "C-1002", "Dock not detecting second monitor", "normal", "open"),
    (503, "C-1003", "Keyboard double-typing on two keys", "high", "open"),
]


class BusinessDB:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS customers (
                id TEXT PRIMARY KEY, name TEXT, email TEXT, tier TEXT);
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY, customer_id TEXT, item TEXT,
                amount_cents INTEGER, status TEXT);
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY, customer_id TEXT, subject TEXT,
                priority TEXT, status TEXT);
            CREATE TABLE IF NOT EXISTS refunds (
                receipt_id TEXT PRIMARY KEY, order_id INTEGER,
                amount_cents INTEGER, idempotency_key TEXT UNIQUE);
            CREATE TABLE IF NOT EXISTS notes (
                receipt_id TEXT PRIMARY KEY, ticket_id INTEGER, body TEXT);
            """
        )
        if self._conn.execute("SELECT COUNT(*) c FROM customers").fetchone()["c"] == 0:
            self._conn.executemany("INSERT INTO customers VALUES (?, ?, ?, ?)", CUSTOMERS)
            self._conn.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?)", ORDERS)
            self._conn.executemany("INSERT INTO tickets VALUES (?, ?, ?, ?, ?)", TICKETS)
            self._conn.commit()

    # queries used by tools -------------------------------------------------
    def search_customers(self, query: str) -> list[dict]:
        q = f"%{query.lower()}%"
        rows = self._conn.execute(
            "SELECT * FROM customers WHERE lower(name) LIKE ? OR lower(email) LIKE ?",
            (q, q),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_order(self, order_id: int) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM orders WHERE id = ?", (order_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_ticket(self, ticket_id: int) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM tickets WHERE id = ?", (ticket_id,)
        ).fetchone()
        return dict(row) if row else None

    def record_refund(self, order_id: int, amount_cents: int,
                      idempotency_key: str) -> str:
        existing = self._conn.execute(
            "SELECT receipt_id FROM refunds WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if existing:  # execute-once: a retry returns the original receipt
            return existing["receipt_id"]
        n = self._conn.execute("SELECT COUNT(*) c FROM refunds").fetchone()["c"]
        receipt = f"RF-{1001 + n}"
        self._conn.execute(
            "INSERT INTO refunds VALUES (?, ?, ?, ?)",
            (receipt, order_id, amount_cents, idempotency_key),
        )
        self._conn.commit()
        return receipt

    def record_note(self, ticket_id: int, body: str) -> str:
        n = self._conn.execute("SELECT COUNT(*) c FROM notes").fetchone()["c"]
        receipt = f"NOTE-{1001 + n}"
        self._conn.execute(
            "INSERT INTO notes VALUES (?, ?, ?)", (receipt, ticket_id, body)
        )
        self._conn.commit()
        return receipt

    def set_ticket_priority(self, ticket_id: int, priority: str) -> None:
        self._conn.execute(
            "UPDATE tickets SET priority = ? WHERE id = ?", (priority, ticket_id)
        )
        self._conn.commit()
