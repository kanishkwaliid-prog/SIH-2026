"""
Human review / consensus layer for Block 2b.

Sits between the LLM's low-confidence guesses and memory.py's permanent
cache (`confirmed_lines`). Instead of a single confirmation immediately
writing to memory (the old behaviour), reviewers submit weighted votes on
a line, and only once enough independent reviewers agree does the answer
get promoted into memory.py's confirmed_lines table.

Uses the SAME database file as memory.py (memory.DB_PATH) -- one file,
extra tables -- so there's nothing new to deploy or keep in sync.

New tables (added to memory.db):
    users            -- role lookup, admin-managed (see seed_user)
    review_staging   -- pending reviewer votes, cleared on promotion
    audit_log        -- hash-chained record of every promotion

Public functions:
    init_review_tables()
    seed_user(user_id, name, role)
    submit_review(raw_line, field, value, submitted_by, vendor_hint=None)
    get_my_reviews(user_id)
    verify_audit_chain()
    generate_report()

Promotion rule: a line is only promoted when BOTH hold:
    1. SUM(points) across reviewers >= THRESHOLD
    2. COUNT(DISTINCT submitted_by) >= MIN_REVIEWERS
So no single reviewer, however senior, can promote a line alone.

Privacy: submitted_by is never exposed except through get_my_reviews(),
which always filters to the caller's own id.
"""

import sqlite3
import hashlib
import json
import time
from contextlib import contextmanager
from typing import Optional

from .memory import DB_PATH, _normalize_line, _encode_value, _decode_value, save_confirmed

# Demo-scope role weights. Adjust to match your team's actual roles.
ROLE_WEIGHTS = {
    "senior_engineer": 3,
    "engineer": 2,
    "user": 1,
}
THRESHOLD = 6
MIN_REVIEWERS = 2


@contextmanager
def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_review_tables():
    """Safe to call repeatedly (CREATE IF NOT EXISTS). Call once at app
    startup, same pattern as memory.init_db()."""
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS review_staging (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                normalized_line TEXT NOT NULL,
                raw_line TEXT NOT NULL,
                field TEXT NOT NULL,
                value_str TEXT,
                value_type TEXT NOT NULL,
                vendor_hint TEXT,
                submitted_by TEXT NOT NULL,
                role TEXT NOT NULL,
                points INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                UNIQUE(normalized_line, submitted_by)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                normalized_line TEXT NOT NULL,
                field TEXT NOT NULL,
                value_str TEXT,
                total_points INTEGER NOT NULL,
                num_reviewers INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
        """)


def seed_user(user_id: str, name: str, role: str):
    """Admin-only. Assigns a reviewer's role ahead of time. NEVER call this
    from a client-facing endpoint -- role must not be client-submitted.
    For the hackathon demo, call this once at startup for each known
    teammate/reviewer (see api.py)."""
    if role not in ROLE_WEIGHTS:
        raise ValueError(f"Unknown role: {role!r}. Must be one of {list(ROLE_WEIGHTS)}")
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO users (user_id, name, role) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET name=excluded.name, role=excluded.role",
            (user_id, name, role)
        )


def _get_role(user_id: str) -> str:
    """Server-side role lookup. A submission's role is ALWAYS taken from
    here, never from the caller -- this is what prevents role-spoofing."""
    with _get_conn() as conn:
        row = conn.execute("SELECT role FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row is None:
        raise ValueError(f"Unknown user_id {user_id!r} -- seed_user() must be called for them first.")
    return row["role"]


def _last_audit_hash() -> str:
    with _get_conn() as conn:
        row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    return row["entry_hash"] if row else "GENESIS"


def _compute_hash(prev_hash: str, payload: dict) -> str:
    blob = prev_hash + json.dumps(payload, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def submit_review(raw_line: str, field: str, value, submitted_by: str,
                   vendor_hint: str = None) -> dict:
    """
    A reviewer votes on what a previously-unclear line should mean.
    Role is looked up server-side -- callers cannot claim a role.

    Returns one of:
      {"status": "rejected", "reason": "duplicate_vote"}
      {"status": "recorded", "total_points": int, "num_reviewers": int}
      {"status": "promoted", "field": str, "value": ...}
    """
    role = _get_role(submitted_by)
    points = ROLE_WEIGHTS[role]
    key = _normalize_line(raw_line)
    value_str, value_type = _encode_value(value)

    with _get_conn() as conn:
        try:
            conn.execute(
                """INSERT INTO review_staging
                   (normalized_line, raw_line, field, value_str, value_type,
                    vendor_hint, submitted_by, role, points, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (key, raw_line, field, value_str, value_type, vendor_hint,
                 submitted_by, role, points, time.time())
            )
        except sqlite3.IntegrityError:
            # UNIQUE(normalized_line, submitted_by) blocked a double-vote
            return {"status": "rejected", "reason": "duplicate_vote"}

    return _check_threshold_and_promote(key)


def _check_threshold_and_promote(normalized_line: str) -> dict:
    with _get_conn() as conn:
        row = conn.execute(
            """SELECT raw_line, field, value_str, value_type, vendor_hint,
                      SUM(points) as total_points, COUNT(DISTINCT submitted_by) as num_reviewers
               FROM review_staging WHERE normalized_line = ?
               GROUP BY normalized_line""",
            (normalized_line,)
        ).fetchone()

    if row is None:
        return {"status": "recorded", "total_points": 0, "num_reviewers": 0}

    total_points = row["total_points"]
    num_reviewers = row["num_reviewers"]

    if total_points < THRESHOLD or num_reviewers < MIN_REVIEWERS:
        return {"status": "recorded", "total_points": total_points, "num_reviewers": num_reviewers}

    final_value = _decode_value(row["value_str"], row["value_type"])
    field = row["field"]

    # Write to memory.py's existing confirmed_lines table -- this is the
    # same cache classify_unknown_line() already checks, so nothing else
    # about the pipeline needs to change.
    save_confirmed(
        row["raw_line"], field, final_value,
        vendor_hint=row["vendor_hint"],
        confirmed_by=f"consensus:{num_reviewers}_reviewers",
        source="human_confirmed",
    )

    now = time.time()
    prev_hash = _last_audit_hash()
    payload = {
        "normalized_line": normalized_line,
        "field": field,
        "value_str": row["value_str"],
        "total_points": total_points,
        "num_reviewers": num_reviewers,
        "timestamp": now,
    }
    entry_hash = _compute_hash(prev_hash, payload)

    with _get_conn() as conn:
        conn.execute(
            """INSERT INTO audit_log
               (normalized_line, field, value_str, total_points, num_reviewers,
                timestamp, prev_hash, entry_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (normalized_line, field, row["value_str"], total_points, num_reviewers,
             now, prev_hash, entry_hash)
        )
        conn.execute("DELETE FROM review_staging WHERE normalized_line = ?", (normalized_line,))

    return {"status": "promoted", "field": field, "value": final_value}


def get_my_reviews(user_id: str) -> list[dict]:
    """The ONLY function that exposes submitted_by-linked data, and only
    for the calling user's own id."""
    with _get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT raw_line, field, value_str, role, points, timestamp "
            "FROM review_staging WHERE submitted_by = ?", (user_id,)
        ).fetchall()]


def verify_audit_chain() -> bool:
    """Recomputes every hash in audit_log in order and confirms the chain
    is unbroken. True = nothing in the audit history has been tampered with."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT normalized_line, field, value_str, total_points, num_reviewers, "
            "timestamp, prev_hash, entry_hash FROM audit_log ORDER BY id ASC"
        ).fetchall()

    running_prev = "GENESIS"
    for row in rows:
        if row["prev_hash"] != running_prev:
            return False
        payload = {
            "normalized_line": row["normalized_line"],
            "field": row["field"],
            "value_str": row["value_str"],
            "total_points": row["total_points"],
            "num_reviewers": row["num_reviewers"],
            "timestamp": row["timestamp"],
        }
        if _compute_hash(row["prev_hash"], payload) != row["entry_hash"]:
            return False
        running_prev = row["entry_hash"]
    return True


def generate_report() -> dict:
    """Safe to expose to anyone -- no reviewer identities included."""
    with _get_conn() as conn:
        promoted = [dict(r) for r in conn.execute(
            "SELECT normalized_line, field, value_str, total_points, num_reviewers, timestamp "
            "FROM audit_log ORDER BY timestamp DESC"
        ).fetchall()]
        pending = [dict(r) for r in conn.execute(
            "SELECT normalized_line, raw_line, field, SUM(points) as total_points, "
            "COUNT(DISTINCT submitted_by) as num_reviewers "
            "FROM review_staging GROUP BY normalized_line"
        ).fetchall()]

    return {
        "promoted": promoted,
        "pending": pending,
        "audit_chain_valid": verify_audit_chain(),
    }