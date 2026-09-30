"""
Human review / consensus layer for Block 2b.

Sits between the LLM's low-confidence guesses and memory.py's permanent
cache (`confirmed_lines`). Instead of a single confirmation immediately
writing to memory (the old behaviour), reviewers submit weighted votes on
a line, and only once enough independent reviewers agree does the answer
get promoted into memory.py's confirmed_lines table.

Uses the SAME database file as memory.py (memory.DB_PATH) -- one file,
extra tables -- so there's nothing new to deploy or keep in sync.

Tables (in memory.db):
    users            -- owned by auth/store.py since Phase 1; read here only
                        to look up a reviewer's role
    review_staging   -- pending reviewer votes, cleared on promotion
    audit_log        -- hash-chained record of every promotion

Tenant isolation (Phase 2): every vote, promotion and audit entry carries
an org_id. Votes only combine with votes from the same org, a promotion
only writes to that org's memory, and each org has its own hash chain
(its first entry links to "GENESIS"). Moving an entry between orgs breaks
both chains, so cross-org tampering is detectable too.

Public functions:
    init_review_tables()
    submit_review(raw_line, field, value, submitted_by, vendor_hint=None, *, org_id)
    get_my_reviews(user_id)
    verify_audit_chain(org_id)
    generate_report(org_id)

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
from auth.config import LEGACY_DATA_ORG, ROLE_VOTE_WEIGHTS

# Vote weight per role. Defined in auth/config.py (Phase 0) so roles live in
# one place. A role missing from this dict (viewer) cannot vote.
ROLE_WEIGHTS = {role.value: weight for role, weight in ROLE_VOTE_WEIGHTS.items()}
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
    startup, after auth.store.init_auth_tables() (which owns `users`).

    Migrates pre-Phase-2 tables (no org_id):
      review_staging -- pending votes are DROPPED. They were cast by the old
                        hardcoded reviewers (alice, bob...) who no longer
                        exist, and keeping them would let ghost votes count
                        toward a real promotion.
      audit_log      -- kept, assigned to LEGACY_DATA_ORG. It was one global
                        chain starting at GENESIS, so it stays a valid chain.
    """
    with _get_conn() as conn:
        staging_cols = {r["name"] for r in conn.execute("PRAGMA table_info(review_staging)")}
        if staging_cols and "org_id" not in staging_cols:
            conn.execute("DROP TABLE review_staging")

        audit_cols = {r["name"] for r in conn.execute("PRAGMA table_info(audit_log)")}
        if audit_cols and "org_id" not in audit_cols:
            conn.execute(
                f"ALTER TABLE audit_log ADD COLUMN org_id TEXT NOT NULL DEFAULT '{LEGACY_DATA_ORG}'"
            )

        conn.execute("""
            CREATE TABLE IF NOT EXISTS review_staging (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id TEXT NOT NULL,
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
                UNIQUE(org_id, normalized_line, submitted_by)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id TEXT NOT NULL,
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_staging_org_line ON review_staging(org_id, normalized_line)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id, id)")


def _get_role(user_id: str, org_id: str) -> str:
    """Server-side role lookup. A submission's role is ALWAYS taken from
    here, never from the caller -- this is what prevents role-spoofing.
    Also refuses a vote cast into an org the reviewer doesn't belong to."""
    with _get_conn() as conn:
        row = conn.execute("SELECT role, org_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row is None:
        raise ValueError(f"Unknown user_id {user_id!r}.")
    if row["org_id"] != org_id:
        raise PermissionError("Reviewers can only vote within their own organization.")
    return row["role"]


def _last_audit_hash(org_id: str) -> str:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT entry_hash FROM audit_log WHERE org_id = ? ORDER BY id DESC LIMIT 1", (org_id,)
        ).fetchone()
    return row["entry_hash"] if row else "GENESIS"


def _compute_hash(prev_hash: str, payload: dict) -> str:
    blob = prev_hash + json.dumps(payload, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def submit_review(raw_line: str, field: str, value, submitted_by: str,
                   vendor_hint: str = None, *, org_id: str) -> dict:
    """
    A reviewer votes on what a previously-unclear line should mean.
    Role is looked up server-side -- callers cannot claim a role.

    Returns one of:
      {"status": "rejected", "reason": "duplicate_vote"}
      {"status": "recorded", "total_points": int, "num_reviewers": int}
      {"status": "promoted", "field": str, "value": ...}
    """
    role = _get_role(submitted_by, org_id)
    if role not in ROLE_WEIGHTS:
        raise PermissionError(f"The {role} role can't vote on unknown lines.")
    points = ROLE_WEIGHTS[role]
    key = _normalize_line(raw_line)
    value_str, value_type = _encode_value(value)

    with _get_conn() as conn:
        try:
            conn.execute(
                """INSERT INTO review_staging
                   (org_id, normalized_line, raw_line, field, value_str, value_type,
                    vendor_hint, submitted_by, role, points, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (org_id, key, raw_line, field, value_str, value_type, vendor_hint,
                 submitted_by, role, points, time.time())
            )
        except sqlite3.IntegrityError:
            # UNIQUE(org_id, normalized_line, submitted_by) blocked a double-vote
            return {"status": "rejected", "reason": "duplicate_vote"}

    return _check_threshold_and_promote(key, org_id, field, value_str, value_type)


def _check_threshold_and_promote(normalized_line: str, org_id: str,
                                 field: str, value_str, value_type: str) -> dict:
    """Tallies the votes that agree with THIS field/value for the line.

    Votes only count together when they agree on the same answer. Grouping
    by line alone (the old behaviour) let one reviewer's "ssh_enabled" and
    another's "telnet_enabled" add up to a promotion of whichever row the
    database happened to return -- consensus on nothing in particular."""
    with _get_conn() as conn:
        row = conn.execute(
            """SELECT raw_line, field, value_str, value_type, vendor_hint,
                      SUM(points) as total_points, COUNT(DISTINCT submitted_by) as num_reviewers
               FROM review_staging
               WHERE org_id = ? AND normalized_line = ? AND field = ? AND value_type = ?
                     AND value_str IS ?
               GROUP BY normalized_line""",
            (org_id, normalized_line, field, value_type, value_str)
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
        org_id=org_id,
    )

    now = time.time()
    prev_hash = _last_audit_hash(org_id)
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
               (org_id, normalized_line, field, value_str, total_points, num_reviewers,
                timestamp, prev_hash, entry_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (org_id, normalized_line, field, row["value_str"], total_points, num_reviewers,
             now, prev_hash, entry_hash)
        )
        conn.execute("DELETE FROM review_staging WHERE org_id = ? AND normalized_line = ?",
                     (org_id, normalized_line))

    return {"status": "promoted", "field": field, "value": final_value}


def get_my_reviews(user_id: str) -> list[dict]:
    """The ONLY function that exposes submitted_by-linked data, and only
    for the calling user's own id."""
    with _get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT raw_line, field, value_str, role, points, timestamp "
            "FROM review_staging WHERE submitted_by = ?", (user_id,)
        ).fetchall()]


def verify_audit_chain(org_id: str) -> bool:
    """Recomputes every hash in this org's audit_log in order and confirms
    the chain is unbroken. True = nothing in its history has been tampered with."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT normalized_line, field, value_str, total_points, num_reviewers, "
            "timestamp, prev_hash, entry_hash FROM audit_log WHERE org_id = ? ORDER BY id ASC",
            (org_id,),
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


def generate_report(org_id: str) -> dict:
    """One org's promotions and pending votes. No reviewer identities
    included, and nothing from any other org."""
    with _get_conn() as conn:
        promoted = [dict(r) for r in conn.execute(
            "SELECT normalized_line, field, value_str, total_points, num_reviewers, timestamp "
            "FROM audit_log WHERE org_id = ? ORDER BY timestamp DESC",
            (org_id,),
        ).fetchall()]
        pending = [dict(r) for r in conn.execute(
            "SELECT normalized_line, raw_line, field, SUM(points) as total_points, "
            "COUNT(DISTINCT submitted_by) as num_reviewers "
            "FROM review_staging WHERE org_id = ? "
            "GROUP BY normalized_line, field, value_type, value_str",
            (org_id,),
        ).fetchall()]

    return {
        "promoted": promoted,
        "pending": pending,
        "audit_chain_valid": verify_audit_chain(org_id),
    }