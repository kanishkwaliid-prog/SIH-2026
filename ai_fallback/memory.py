"""
ai_fallback.memory
-------------------
Phase 5 — persistent "already learned" store for unrecognized config
lines (``ComplianceResult.unrecognized_lines`` from
``converter/schema_adapter.py``).

SQLite table keyed on ``(vendor, line_pattern) -> confirmed_category``.

``vendor`` here MUST be ``ComplianceResult.vendor`` (the specific codec
id, e.g. ``"cisco_iosxe_cli"``), never ``vendor_family`` -- see
schema_adapter.py's docstring on why the two diverge. Keeping vendor
keying consistent with how remediation lookups work elsewhere in this
project means a pattern confirmed for ``cisco_iosxe_cli`` is never
silently reused for the NETCONF-only ``cisco_iosxe`` codec, which has a
completely different line shape.

A "line_pattern" is NOT the raw line -- two lines that only differ by a
concrete value (an IP, a port number, a quoted hostname) should still
hit the same memory entry, otherwise every device with slightly
different addressing would re-trigger an AI call / human review for
config syntax that's already been confirmed once.
``normalize_line_to_pattern()`` does that generalisation. If this
normalization ever proves too aggressive (two genuinely different
settings collapsing onto the same pattern), tighten the regexes here --
don't work around it by keying on raw lines, which would defeat the
point of the memory table.
"""

from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "learned_mappings.db"

# Keep this in sync with the category list in ai_fallback/classify.py's
# prompt -- both the human-confirm path (here) and the AI-guess path
# (classify.py) must only ever produce one of these.
VALID_CATEGORIES = frozenset({
    "ssh_enabled",
    "telnet_enabled",
    "session_timeout_seconds",
    "logging_enabled",
    "password_encryption",
    "banner_configured",
    "unclear",
})

_RE_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
_RE_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_RE_QUOTED = re.compile(r'"[^"]*"|\'[^\']*\'')
_RE_HEXBLOB = re.compile(r"\b0x[0-9a-fA-F]+\b")
_RE_NUMBER = re.compile(r"\b\d+\b")
_RE_WS = re.compile(r"\s+")


def normalize_line_to_pattern(line: str) -> str:
    """Collapse a raw config line into a reusable pattern.

    Concrete values (IPs, MACs, quoted strings, hex blobs, bare
    numbers) are replaced with placeholders and whitespace/case is
    normalized, so structurally identical lines from different
    devices map to the same memory entry.
    """
    s = line.strip()
    s = _RE_IPV4.sub("<IP>", s)
    s = _RE_MAC.sub("<MAC>", s)
    s = _RE_QUOTED.sub("<STR>", s)
    s = _RE_HEXBLOB.sub("<HEX>", s)
    s = _RE_NUMBER.sub("<NUM>", s)
    s = _RE_WS.sub(" ", s).strip().lower()
    return s


@dataclass(frozen=True)
class KnownMapping:
    vendor: str
    line_pattern: str
    confirmed_category: str
    example_line: str
    confirmed_count: int
    first_confirmed_at: str
    last_confirmed_at: str


class MemoryStore:
    """Thin wrapper around the SQLite table of confirmed line mappings."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self.db_path = str(db_path)
        with closing(self._connect()) as conn:
            self._ensure_schema(conn)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _ensure_schema(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS known_mappings (
                vendor              TEXT NOT NULL,
                line_pattern        TEXT NOT NULL,
                confirmed_category  TEXT NOT NULL,
                example_line        TEXT NOT NULL,
                confirmed_count     INTEGER NOT NULL DEFAULT 1,
                first_confirmed_at  TEXT NOT NULL,
                last_confirmed_at   TEXT NOT NULL,
                PRIMARY KEY (vendor, line_pattern)
            )
            """
        )
        conn.commit()

    def check_known_mapping(self, vendor: str, line: str) -> str | None:
        """Return the confirmed category for *line* under *vendor*, or
        None on a memory miss. Pure lookup -- never calls the AI or a
        human."""
        pattern = normalize_line_to_pattern(line)
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT confirmed_category FROM known_mappings "
                "WHERE vendor = ? AND line_pattern = ?",
                (vendor, pattern),
            ).fetchone()
        return row["confirmed_category"] if row else None

    def save_confirmed(self, vendor: str, line: str, confirmed_category: str) -> None:
        """Persist a human-confirmed (or human-corrected) category for
        *line* under *vendor*, permanently. Safe to call repeatedly for
        the same pattern -- bumps the confirmation count instead of
        duplicating rows."""
        if confirmed_category not in VALID_CATEGORIES:
            raise ValueError(
                f"'{confirmed_category}' is not a valid category "
                f"(expected one of {sorted(VALID_CATEGORIES)})"
            )
        pattern = normalize_line_to_pattern(line)
        now = datetime.now(timezone.utc).isoformat()
        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT INTO known_mappings
                    (vendor, line_pattern, confirmed_category, example_line,
                     confirmed_count, first_confirmed_at, last_confirmed_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(vendor, line_pattern) DO UPDATE SET
                    confirmed_category = excluded.confirmed_category,
                    confirmed_count = known_mappings.confirmed_count + 1,
                    last_confirmed_at = excluded.last_confirmed_at
                """,
                (vendor, pattern, confirmed_category, line.strip(), now, now),
            )
            conn.commit()

    def get_mapping(self, vendor: str, line: str) -> KnownMapping | None:
        """Full record lookup (for debugging / the Phase 5.6 review UI)."""
        pattern = normalize_line_to_pattern(line)
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM known_mappings WHERE vendor = ? AND line_pattern = ?",
                (vendor, pattern),
            ).fetchone()
        return KnownMapping(**dict(row)) if row else None

    def all_mappings(self, vendor: str | None = None) -> list[KnownMapping]:
        query = "SELECT * FROM known_mappings"
        params: tuple = ()
        if vendor is not None:
            query += " WHERE vendor = ?"
            params = (vendor,)
        query += " ORDER BY vendor, line_pattern"
        with closing(self._connect()) as conn:
            rows = conn.execute(query, params).fetchall()
        return [KnownMapping(**dict(r)) for r in rows]
