"""
Phase 0 -- auth decisions, encoded as code.

Every later phase imports its constants from here instead of hardcoding
them, so a decision changes in exactly one place. The reasoning behind
each value lives in docs/auth_decisions.md.

Nothing in this file touches the database or the request cycle.
"""

import os
from enum import Enum

from dotenv import load_dotenv

load_dotenv()


# ---------- Roles ----------
# Replaces the old senior_engineer / engineer / user set that lived in
# block2b/review_system.py. "user" is gone: it becomes "viewer", which
# can read reports but cannot vote on unknown lines.

class Role(str, Enum):
    ADMIN = "admin"
    SENIOR_ENGINEER = "senior_engineer"
    ENGINEER = "engineer"
    VIEWER = "viewer"


# Signup always creates a NEW org, and the person signing up becomes its
# admin. You can't sign yourself into an existing org -- that would let
# anyone read another company's reports. Joining an existing org happens
# only when that org's admin adds you (Phase 4), with whatever role the
# admin picks, defaulting to viewer.
SIGNUP_CREATES_ORG_AS = Role.ADMIN
DEFAULT_MEMBER_ROLE = Role.VIEWER


# ---------- Review vote weights ----------
# Consumed by review_system.py from Phase 1 onward (it will import this
# instead of keeping its own ROLE_WEIGHTS). A role missing from this dict
# cannot vote at all. THRESHOLD / MIN_REVIEWERS stay in review_system.py.
#   admin + senior      = 6 -> promotes
#   engineer x 2        = 4 -> does not
#   engineer x 3        = 6 -> promotes
ROLE_VOTE_WEIGHTS: dict[Role, int] = {
    Role.ADMIN: 3,
    Role.SENIOR_ENGINEER: 3,
    Role.ENGINEER: 2,
}


# ---------- Permissions ----------
# Endpoints check a permission, never a role name (Phase 4:
# require_permission(Permission.UPLOAD)). Changing who can do what means
# editing ROLE_PERMISSIONS below, not touching api.py.

class Permission(str, Enum):
    UPLOAD = "upload"                  # POST /upload
    CONFIRM = "confirm"                # POST /confirm (cast review votes)
    EVALUATE = "evaluate"              # POST /evaluate/{session_id}
    VIEW_REPORTS = "view_reports"      # GET /report/{id}/pdf, GET /review/report
    VIEW_AUDIT_LOG = "view_audit_log"  # GET /audit (Phase 5)
    MANAGE_USERS = "manage_users"      # /admin/users (Phase 4)


_ANALYST = {Permission.UPLOAD, Permission.CONFIRM, Permission.EVALUATE, Permission.VIEW_REPORTS}

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),  # everything
    Role.SENIOR_ENGINEER: frozenset(_ANALYST | {Permission.VIEW_AUDIT_LOG}),
    Role.ENGINEER: frozenset(_ANALYST),
    Role.VIEWER: frozenset({Permission.VIEW_REPORTS}),
}


def has_permission(role: str, permission: Permission) -> bool:
    """False for unknown roles rather than raising, so a stale or tampered
    role string fails closed."""
    try:
        return permission in ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return False


# ---------- Tokens (JWT) ----------

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 60
MFA_PENDING_TOKEN_MINUTES = 5  # the half-logged-in token between password and TOTP

# Value of the "type" claim. get_current_user accepts ONLY "access"; an
# mfa_pending token is useless anywhere except POST /auth/2fa/login.
TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_MFA_PENDING = "mfa_pending"

MIN_SECRET_LENGTH = 32


def get_jwt_secret() -> str:
    """Read lazily (not at import) so tests can set the env var first.
    Fails loudly instead of silently signing tokens with a weak key."""
    secret = os.getenv("JWT_SECRET", "")
    if len(secret) < MIN_SECRET_LENGTH:
        raise RuntimeError(
            f"JWT_SECRET must be set in .env and be at least {MIN_SECRET_LENGTH} characters. "
            'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )
    return secret


# ---------- Brute-force protection ----------
# Counted per account, for both password and TOTP failures.
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5


# ---------- 2FA ----------
TOTP_ISSUER = "ConfigGuard"   # name shown in Google Authenticator / Authy
TOTP_VALID_WINDOW = 1         # accept the previous/next 30s code (clock drift)
BACKUP_CODE_COUNT = 8


# ---------- Tenancy ----------
# A tenant is a single org_id string on the user. Everything the app stores
# (sessions, learned lines, review votes, both audit logs) is stamped with
# it, and org_id is always taken from the token, never from the request.
# Learned-line memory is per org: one org's confirmed lines never resolve
# or appear for another org.
MEMORY_SCOPE = "per_org"

# Learned lines and promotion history recorded BEFORE organisations existed
# are migrated into this org (the alpha demo org) so the demo keeps them.
LEGACY_DATA_ORG = "org_alpha"
