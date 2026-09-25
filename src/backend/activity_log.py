"""
Append-only, tamper-evident activity log (Phase 5).

Records who did what, in which org, chained the SAME way
block2b/review_system.py chains its audit_log: every row's entry_hash
covers prev_hash + sha256(json.dumps(payload, sort_keys=True)), the first
row in each org's chain links to "GENESIS", and re-walking the chain in id
order catches any row that was edited after the fact. _compute_hash is
imported from review_system rather than reimplemented, so both chains are
guaranteed to hash the same way even if that function ever changes.

This is a DIFFERENT table from review_system's audit_log (which records
review-line promotions only, not general activity) -- do not confuse the
two or reuse the name.

One row per event:
    id, org_id, actor_user_id, actor_role, event_type, target, detail,
    timestamp, prev_hash, entry_hash

actor_user_id/actor_role are NULL for the one case where nobody is
authenticated yet: a failed login. See log_event()'s docstring.

Public functions:
    init_activity_log_table()
    log_event(user, event_type, target=None, detail=None, *, org_id=None)
    list_activity_log(org_id, limit=50, before_id=None)
    verify_activity_chain(org_id)
"""

import json
import logging
import sqlite3
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Optional

from block2b.memory import DB_PATH
from block2b.review_system import _compute_hash

if TYPE_CHECKING:
    from auth.store import User

_logger = logging.getLogger("activity_log")

GENESIS = "GENESIS"
MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50


@contextmanager
def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_activity_log_table():
    """Safe to call on every startup. Call AFTER auth.store.init_auth_tables()
    (this table's org_id references the orgs table that creates)."""
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id TEXT NOT NULL REFERENCES orgs(org_id),
                actor_user_id TEXT,
                actor_role TEXT,
                event_type TEXT NOT NULL,
                target TEXT,
                detail TEXT,
                timestamp REAL NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_org ON activity_log(org_id, id)")


def _last_hash(org_id: str) -> str:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT entry_hash FROM activity_log WHERE org_id = ? ORDER BY id DESC LIMIT 1",
            (org_id,),
        ).fetchone()
    return row["entry_hash"] if row else GENESIS


def log_event(
    user: "Optional[User]",
    event_type: str,
    target: Optional[str] = None,
    detail: Optional[dict] = None,
    *,
    org_id: Optional[str] = None,
) -> bool:
    """Appends one entry to an org's activity log.

    Two ways to call it:

      log_event(user, "upload", target=session_id, detail={...})
          The normal case -- `user` is the authenticated actor. org_id,
          actor_user_id and actor_role are all read from `user`; any
          org_id passed explicitly is ignored, so a caller can never log
          into an org other than the acting user's own.

      log_event(None, "login_failure", target=attempted_email, org_id=org_id)
          For the one flow where nobody is authenticated yet: a failed
          login. `user` is None, so actor_user_id and actor_role are left
          NULL -- a failed attempt has no legitimate actor to name, and
          logging a user_id here would misleadingly suggest one. org_id
          must be supplied by the caller from wherever it already
          resolved the account (e.g. the email matched a real user, just
          with the wrong password). If no org can be determined at all
          (the email doesn't belong to any account), there is no tenant
          to log into -- do not call this function in that case; there is
          nothing to attribute the attempt to.

    NEVER raises. An audit log must not become a way to break the action
    it's watching: any failure here (a locked database, a bad DB_PATH,
    whatever) is caught and reported to the "activity_log" logger, and
    the caller's request proceeds as if nothing happened. Returns True if
    the entry was written, False otherwise -- callers are not expected to
    check this; it exists mainly so tests can tell the two apart.
    """
    try:
        if user is not None:
            org_id = user.org_id
            actor_user_id = user.user_id
            actor_role = user.role
        else:
            actor_user_id = None
            actor_role = None

        if not org_id:
            raise ValueError("log_event needs either `user` or an explicit org_id.")

        detail_json = json.dumps(detail, sort_keys=True) if detail is not None else None
        now = time.time()
        prev_hash = _last_hash(org_id)
        payload = {
            "actor_user_id": actor_user_id,
            "actor_role": actor_role,
            "event_type": event_type,
            "target": target,
            "detail": detail_json,
            "timestamp": now,
        }
        entry_hash = _compute_hash(prev_hash, payload)

        with _get_conn() as conn:
            conn.execute(
                """INSERT INTO activity_log
                   (org_id, actor_user_id, actor_role, event_type, target, detail,
                    timestamp, prev_hash, entry_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (org_id, actor_user_id, actor_role, event_type, target, detail_json,
                 now, prev_hash, entry_hash),
            )
        return True
    except Exception:
        _logger.exception(
            "Failed to record activity log event %r (org_id=%r) -- the action it "
            "describes still went ahead.", event_type, org_id,
        )
        return False


def list_activity_log(org_id: str, limit: int = DEFAULT_PAGE_SIZE,
                      before_id: Optional[int] = None) -> dict:
    """One page of an org's activity log, newest first. Never returns the
    whole table: `limit` is clamped to MAX_PAGE_SIZE. Pass the response's
    `next_before_id` back in as `before_id` to fetch the next page."""
    limit = max(1, min(limit, MAX_PAGE_SIZE))
    query = (
        "SELECT id, actor_user_id, actor_role, event_type, target, detail, timestamp "
        "FROM activity_log WHERE org_id = ?"
    )
    params: list = [org_id]
    if before_id is not None:
        query += " AND id < ?"
        params.append(before_id)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit + 1)  # one extra row -> cheap way to know if there's a next page

    with _get_conn() as conn:
        rows = conn.execute(query, params).fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]
    entries = [
        {
            "id": r["id"],
            "actor_user_id": r["actor_user_id"],
            "actor_role": r["actor_role"],
            "event_type": r["event_type"],
            "target": r["target"],
            "detail": json.loads(r["detail"]) if r["detail"] else None,
            "timestamp": r["timestamp"],
        }
        for r in rows
    ]
    return {
        "entries": entries,
        "has_more": has_more,
        "next_before_id": entries[-1]["id"] if (has_more and entries) else None,
    }


def verify_activity_chain(org_id: str) -> bool:
    """Recomputes every hash in this org's activity_log in order and
    confirms the chain is unbroken. True = nothing in its history (who did
    what, or the order they did it in) has been tampered with."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT actor_user_id, actor_role, event_type, target, detail, timestamp, "
            "prev_hash, entry_hash FROM activity_log WHERE org_id = ? ORDER BY id ASC",
            (org_id,),
        ).fetchall()

    running_prev = GENESIS
    for row in rows:
        if row["prev_hash"] != running_prev:
            return False
        payload = {
            "actor_user_id": row["actor_user_id"],
            "actor_role": row["actor_role"],
            "event_type": row["event_type"],
            "target": row["target"],
            "detail": row["detail"],
            "timestamp": row["timestamp"],
        }
        if _compute_hash(row["prev_hash"], payload) != row["entry_hash"]:
            return False
        running_prev = row["entry_hash"]
    return True
