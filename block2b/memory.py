"""
Memory layer for the classifier.

Stores human-confirmed line -> field/value mappings in SQLite so the
same config line (seen again on this device or another) doesn't need
another LLM call. Two entry points matter to the rest of the app:

    check_memory(raw_line)          -> dict result or None
    save_confirmed(raw_line, ...)   -> writes a confirmed mapping

Everything else in this file is implementation detail.
"""

import sqlite3
import re
from contextlib import contextmanager
from typing import Optional

DB_PATH = "memory.db"


def _normalize_line(raw_line: str) -> str:
    """
    Collapse whitespace and lowercase, so lines that differ only in
    spacing/case still hit the same cache entry. We deliberately do NOT
    strip things like interface numbers or IPs -- "exec-timeout 10 0"
    and "exec-timeout 5 0" are different settings and must not collide.
    """
    return re.sub(r"\s+", " ", raw_line.strip()).lower()


@contextmanager
def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Call once at app startup. Safe to call repeatedly (CREATE IF NOT EXISTS)."""
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS confirmed_lines (
                normalized_line TEXT PRIMARY KEY,
                raw_line TEXT NOT NULL,
                field TEXT NOT NULL,
                value TEXT,             -- stored as JSON-ish text, see _encode/_decode below
                value_type TEXT NOT NULL, -- "bool" | "int" | "str" | "none"
                vendor_hint TEXT,
                confirmed_by TEXT,       -- optional: who confirmed it, if you track users
                source TEXT DEFAULT 'human_confirmed'  -- 'human_confirmed' | 'llm_high_confidence'
            )
        """)


def _encode_value(value) -> tuple[Optional[str], str]:
    if value is None:
        return None, "none"
    if isinstance(value, bool):
        return ("true" if value else "false"), "bool"
    if isinstance(value, int):
        return str(value), "int"
    return str(value), "str"


def _decode_value(value_str: Optional[str], value_type: str):
    if value_type == "none" or value_str is None:
        return None
    if value_type == "bool":
        return value_str == "true"
    if value_type == "int":
        return int(value_str)
    return value_str


def check_memory(raw_line: str, vendor_hint: str = None) -> Optional[dict]:
    """
    Look up a previously confirmed classification for this exact line.
    Returns a dict shaped like classify_unknown_line()'s normal return
    value (field/value/confidence/reasoning), or None if not found.

    vendor_hint is currently informational only (stored, not part of the
    lookup key) -- config lines like "transport input ssh" mean the same
    thing regardless of vendor. If that assumption turns out wrong for
    some field, key vendor in separately -- flag it to the team first
    since it changes the cache key shape.
    """
    key = _normalize_line(raw_line)
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM confirmed_lines WHERE normalized_line = ?", (key,)
        ).fetchone()

    if row is None:
        return None

    return {
        "field": row["field"],
        "value": _decode_value(row["value"], row["value_type"]),
        "confidence": 1.0,  # human-confirmed (or previously high-confidence) = treat as certain
        "reasoning": f"From memory (originally {row['source']})",
    }


def save_confirmed(raw_line: str, field: str, value, vendor_hint: str = None,
                    confirmed_by: str = None, source: str = "human_confirmed"):
    """
    Save a confirmed field/value mapping for this line so future runs
    skip the LLM call. Call this after a human confirms a result on the
    review-unknown-lines screen, passing the (possibly corrected) field
    and value they approved -- not necessarily what the LLM originally
    guessed.
    """
    key = _normalize_line(raw_line)
    value_str, value_type = _encode_value(value)

    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO confirmed_lines
                (normalized_line, raw_line, field, value, value_type, vendor_hint, confirmed_by, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(normalized_line) DO UPDATE SET
                raw_line=excluded.raw_line,
                field=excluded.field,
                value=excluded.value,
                value_type=excluded.value_type,
                vendor_hint=excluded.vendor_hint,
                confirmed_by=excluded.confirmed_by,
                source=excluded.source
        """, (key, raw_line, field, value_str, value_type, vendor_hint, confirmed_by, source))


def forget(raw_line: str):
    """Remove a cached entry -- useful if a confirmation turns out to be wrong."""
    key = _normalize_line(raw_line)
    with _get_conn() as conn:
        conn.execute("DELETE FROM confirmed_lines WHERE normalized_line = ?", (key,))