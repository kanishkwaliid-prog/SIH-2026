"""
User and organisation storage.

Lives in the same SQLite file as the rest of the app (block2b/memory.py's
DB_PATH), as two tables:

    orgs   (org_id, name, created_at)
    users  (user_id, email, name, password_hash, org_id, role,
            totp_secret, totp_enabled, created_at)

`users` replaces the old three-column table that review_system.py used to
create and seed with alice/bob/carol. init_auth_tables() detects that old
shape and drops it -- it only ever held hardcoded demo reviewers.

Password hashes never leave this module except through get_credentials(),
which only the login route calls.
"""

import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional

from block2b import memory

from . import security
from .config import Role

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_EMAIL_LENGTH = 254


class EmailAlreadyRegistered(Exception):
    pass


@dataclass(frozen=True)
class User:
    user_id: str
    email: str
    name: str
    org_id: str
    role: str
    totp_enabled: bool

    def public(self) -> dict:
        """The only shape a user is ever sent to the client in."""
        return {
            "user_id": self.user_id,
            "email": self.email,
            "name": self.name,
            "org_id": self.org_id,
            "role": self.role,
            "totp_enabled": self.totp_enabled,
        }


@contextmanager
def _get_conn():
    # memory.DB_PATH is read on every call (not imported by value) so tests
    # can point the whole app at a temporary database.
    conn = sqlite3.connect(memory.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def is_valid_email(email: str) -> bool:
    return len(email) <= MAX_EMAIL_LENGTH and bool(EMAIL_RE.match(email))


def _row_to_user(row: sqlite3.Row) -> User:
    return User(
        user_id=row["user_id"],
        email=row["email"],
        name=row["name"],
        org_id=row["org_id"],
        role=row["role"],
        totp_enabled=bool(row["totp_enabled"]),
    )


# ---------- Schema ----------

def init_auth_tables():
    """Safe to call on every startup. Call BEFORE review_system's tables."""
    with _get_conn() as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        if cols and "email" not in cols:
            # Pre-auth demo table (user_id, name, role). Nothing real in it.
            conn.execute("DROP TABLE users")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS orgs (
                org_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                org_id TEXT NOT NULL REFERENCES orgs(org_id),
                role TEXT NOT NULL,
                totp_secret TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id)")

        # Phase 3: replay protection needs one more column on an existing
        # table, added the same "detect and migrate" way as everything else.
        user_cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        if "totp_last_step" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS backup_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL REFERENCES users(user_id),
                code_hash TEXT NOT NULL UNIQUE,
                created_at REAL NOT NULL,
                used_at REAL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_codes_user ON backup_codes(user_id)")


# ---------- Writes ----------

def _insert_user(conn, email, name, password_hash, org_id, role) -> User:
    user_id = "usr_" + uuid.uuid4().hex[:16]
    try:
        conn.execute(
            "INSERT INTO users (user_id, email, name, password_hash, org_id, role, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, email, name, password_hash, org_id, Role(role).value, time.time()),
        )
    except sqlite3.IntegrityError as exc:
        if "users.email" in str(exc):
            raise EmailAlreadyRegistered(email) from exc
        raise
    return User(user_id, email, name, org_id, Role(role).value, False)


def create_org_with_admin(org_name: str, email: str, name: str, password: str, role: Role) -> User:
    """Signup: new org + its first user, in one transaction so a duplicate
    email never leaves an empty org behind. Hash is computed before the
    transaction opens so the DB isn't locked during argon2."""
    email = normalize_email(email)
    password_hash = security.hash_password(password)
    org_id = "org_" + uuid.uuid4().hex[:12]
    with _get_conn() as conn:
        conn.execute("INSERT INTO orgs (org_id, name, created_at) VALUES (?, ?, ?)",
                     (org_id, org_name, time.time()))
        return _insert_user(conn, email, name, password_hash, org_id, role)


def create_user_in_org(org_id: str, email: str, name: str, password: str, role: Role) -> User:
    """For admins adding members (Phase 4) and for demo seeding."""
    email = normalize_email(email)
    password_hash = security.hash_password(password)
    with _get_conn() as conn:
        return _insert_user(conn, email, name, password_hash, org_id, role)


def update_password_hash(user_id: str, password_hash: str):
    with _get_conn() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (password_hash, user_id))


# ---------- Reads ----------

def get_user_by_id(user_id: str) -> Optional[User]:
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    return _row_to_user(row) if row else None


def get_credentials(email: str) -> Optional[tuple[User, str]]:
    """(user, password_hash) for login only."""
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (normalize_email(email),)).fetchone()
    return (_row_to_user(row), row["password_hash"]) if row else None


# ---------- Member management (Phase 4) ----------
# Every function takes org_id and scopes its SQL by it, so an admin can
# never read or touch a user outside their own organisation.

class UserNotFound(Exception):
    pass


class LastAdminError(Exception):
    """Raised when a change would leave an organisation with no admin."""


def list_org_users(org_id: str) -> list[User]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM users WHERE org_id = ? ORDER BY created_at ASC, email ASC", (org_id,)
        ).fetchall()
    return [_row_to_user(r) for r in rows]


def get_org_user(org_id: str, user_id: str) -> Optional[User]:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE user_id = ? AND org_id = ?", (user_id, org_id)
        ).fetchone()
    return _row_to_user(row) if row else None


def set_user_role(org_id: str, user_id: str, role: Role) -> User:
    """Changes a member's role. Refuses to demote the org's last admin.
    The check and the write share one transaction (BEGIN IMMEDIATE takes
    the write lock first) so two concurrent demotions can't both pass."""
    role = Role(role)
    conn = sqlite3.connect(memory.DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT role FROM users WHERE user_id = ? AND org_id = ?", (user_id, org_id)
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            raise UserNotFound(user_id)
        if row["role"] == Role.ADMIN.value and role is not Role.ADMIN:
            admins = conn.execute(
                "SELECT COUNT(*) AS n FROM users WHERE org_id = ? AND role = ?",
                (org_id, Role.ADMIN.value),
            ).fetchone()["n"]
            if admins <= 1:
                conn.execute("ROLLBACK")
                raise LastAdminError(user_id)
        conn.execute("UPDATE users SET role = ? WHERE user_id = ?", (role.value, user_id))
        conn.execute("COMMIT")
    finally:
        conn.close()
    return get_org_user(org_id, user_id)


def reset_user_totp(org_id: str, user_id: str) -> User:
    """Admin recovery for a member who lost their phone AND their backup
    codes: turns 2FA off and deletes their backup codes. The member signs
    in with just their password and can enrol again."""
    user = get_org_user(org_id, user_id)
    if user is None:
        raise UserNotFound(user_id)
    disable_totp(user_id)
    return get_org_user(org_id, user_id)


# ---------- 2FA (Phase 3) ----------
# The secret and totp_last_step never leave this module -- only auth.totp
# and the functions below touch them. Everything else sees totp_enabled
# via User.public(), never the secret itself.

@dataclass(frozen=True)
class TotpState:
    secret: Optional[str]
    enabled: bool
    last_step: int


def set_pending_totp_secret(user_id: str, secret: str) -> None:
    """Starts (or restarts) enrollment: stores an unconfirmed secret,
    leaves totp_enabled untouched at 0, and resets replay protection so a
    stale step from a previous attempt can't block a fresh one."""
    with _get_conn() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = ?, totp_last_step = 0 WHERE user_id = ?",
            (secret, user_id),
        )


def get_totp_state(user_id: str) -> Optional[TotpState]:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT totp_secret, totp_enabled, totp_last_step FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    if row is None:
        return None
    return TotpState(row["totp_secret"], bool(row["totp_enabled"]), row["totp_last_step"])


def enable_totp(user_id: str, code_hashes: list[str]) -> bool:
    """One transaction: flips totp_enabled on and stores the backup code
    hashes, so a crash between the two can never leave 2FA on with no
    recovery codes. Returns False (writing nothing) if 2FA was already on,
    so two simultaneous /verify calls can't each add a set of codes."""
    now = time.time()
    with _get_conn() as conn:
        cur = conn.execute(
            "UPDATE users SET totp_enabled = 1 WHERE user_id = ? AND totp_enabled = 0", (user_id,)
        )
        if cur.rowcount == 0:
            return False
        conn.executemany(
            "INSERT INTO backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
            [(user_id, h, now) for h in code_hashes],
        )
        return True


def record_totp_step(user_id: str, step: int) -> bool:
    """Advances totp_last_step to `step` and returns True, or returns False
    if it was already >= step. The WHERE clause makes this an atomic
    compare-and-set: of two simultaneous requests carrying the same code,
    exactly one sees rowcount 1. Callers MUST treat False as a replay and
    reject the login -- ignoring the result defeats the protection."""
    with _get_conn() as conn:
        cur = conn.execute(
            "UPDATE users SET totp_last_step = ? WHERE user_id = ? AND totp_last_step < ?",
            (step, user_id, step),
        )
        return cur.rowcount > 0


def use_backup_code(user_id: str, code_hash: str) -> bool:
    """Marks a code used and returns True only if it existed, belonged to
    this user, and was unused -- so one code can never be spent twice."""
    with _get_conn() as conn:
        cur = conn.execute(
            "UPDATE backup_codes SET used_at = ? "
            "WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
            (time.time(), user_id, code_hash),
        )
        return cur.rowcount > 0


def count_unused_backup_codes(user_id: str) -> int:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = ? AND used_at IS NULL",
            (user_id,),
        ).fetchone()
    return row["n"]


def replace_backup_codes(user_id: str, code_hashes: list[str]) -> None:
    now = time.time()
    with _get_conn() as conn:
        conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
        conn.executemany(
            "INSERT INTO backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
            [(user_id, h, now) for h in code_hashes],
        )


def disable_totp(user_id: str) -> None:
    with _get_conn() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = 0 "
            "WHERE user_id = ?",
            (user_id,),
        )
        conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))


# ---------- Demo data ----------

DEMO_ORGS = {
    "org_alpha": ("Alpha Networks", "alpha"),
    "org_beta": ("Beta Telecom", "beta"),
}
DEMO_ROLES = {
    Role.ADMIN: "admin",
    Role.SENIOR_ENGINEER: "senior",
    Role.ENGINEER: "engineer",
    Role.VIEWER: "viewer",
}


def demo_accounts() -> list[tuple[str, str, str, Role]]:
    """(org_id, email, display name, role), e.g. engineer@alpha.demo."""
    out = []
    for org_id, (org_name, slug) in DEMO_ORGS.items():
        for role, local in DEMO_ROLES.items():
            name = f"{org_name.split()[0]} {local.capitalize()}"
            out.append((org_id, f"{local}@{slug}.demo", name, role))
    return out


def seed_demo_accounts(password: str) -> int:
    """Idempotent. Creates the two demo orgs and one account per role in
    each. If DEMO_PASSWORD changed since last run, existing demo accounts
    are updated to the new password. Returns how many accounts it created."""
    created = 0
    with _get_conn() as conn:
        for org_id, (org_name, _) in DEMO_ORGS.items():
            conn.execute("INSERT OR IGNORE INTO orgs (org_id, name, created_at) VALUES (?, ?, ?)",
                         (org_id, org_name, time.time()))

    for org_id, email, name, role in demo_accounts():
        existing = get_credentials(email)
        if existing is None:
            create_user_in_org(org_id, email, name, password, role)
            created += 1
        elif not security.verify_password(existing[1], password):
            update_password_hash(existing[0].user_id, security.hash_password(password))
    return created
