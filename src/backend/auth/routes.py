"""
/auth routes. Request and response shapes match section 9 of
docs/auth_decisions.md -- change both together.
"""

import threading
import time

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

import activity_log
from . import config, lockout, security, store, totp
from .deps import get_current_user
from .store import User

router = APIRouter(prefix="/auth", tags=["auth"])

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128  # caps the work an attacker can make argon2 do per request

BAD_CREDENTIALS = "Incorrect email or password."


def _clean_email(value: str) -> str:
    value = store.normalize_email(value)
    if not store.is_valid_email(value):
        raise ValueError("Enter a valid email address.")
    return value


class SignupRequest(BaseModel):
    email: str
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)
    name: str
    org_name: str

    @field_validator("email")
    @classmethod
    def _email(cls, v):
        return _clean_email(v)

    @field_validator("password")
    @classmethod
    def _password(cls, v):
        if len(v) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return v

    @field_validator("name", "org_name")
    @classmethod
    def _text(cls, v):
        v = v.strip()
        if not 1 <= len(v) <= 100:
            raise ValueError("Must be between 1 and 100 characters.")
        return v


class LoginRequest(BaseModel):
    email: str = Field(max_length=store.MAX_EMAIL_LENGTH)
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)


def _login_success(user: User) -> dict:
    return {
        "status": "ok",
        "access_token": security.create_access_token(user),
        "token_type": "bearer",
        "expires_in": config.ACCESS_TOKEN_MINUTES * 60,
        "user": user.public(),
    }


@router.post("/signup", status_code=status.HTTP_201_CREATED)
def signup(body: SignupRequest):
    """Creates a NEW organisation with the caller as its admin. There is
    deliberately no way to sign up into an existing org."""
    try:
        user = store.create_org_with_admin(
            org_name=body.org_name, email=body.email, name=body.name,
            password=body.password, role=config.SIGNUP_CREATES_ORG_AS,
        )
    except store.EmailAlreadyRegistered:
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists.")
    return user.public()


@router.post("/login")
def login(body: LoginRequest):
    key = store.normalize_email(body.email)

    wait = lockout.seconds_locked(key)
    if wait:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many failed attempts. Try again in {max(1, round(wait / 60))} minute(s).",
            headers={"Retry-After": str(wait)},
        )

    found = store.get_credentials(key)
    if found is None:
        security.waste_verify_time(body.password)
        lockout.record_failure(key)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, BAD_CREDENTIALS)

    user, password_hash = found
    if not security.verify_password(password_hash, body.password):
        lockout.record_failure(key)
        # Email resolved to a real account (so its org_id is known) but the
        # password was wrong. Only the attempted email is logged, never a
        # user_id -- see activity_log.log_event's docstring. An email that
        # doesn't match any account at all has no org to log the attempt
        # into, so that branch above logs nothing.
        activity_log.log_event(None, "login_failure", target=key, org_id=user.org_id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, BAD_CREDENTIALS)

    lockout.reset(key)
    if security.needs_rehash(password_hash):
        store.update_password_hash(user.user_id, security.hash_password(body.password))

    if user.totp_enabled:
        return {"status": "mfa_required", "mfa_token": security.create_mfa_pending_token(user)}
    activity_log.log_event(user, "login_success", detail={"mfa": False})
    return _login_success(user)


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user.public()


# ---------- Phase 3: two-factor authentication ----------

# Makes an mfa_pending token single-use: once /auth/2fa/login SUCCEEDS with
# a given jti, that jti is recorded here so a second attempt (e.g. a
# replayed request) is rejected even though the token itself hasn't
# expired yet. A WRONG code does not spend the token -- the user can retype
# it without re-entering their password (the login page relies on this);
# guessing is bounded by the mfa:<user_id> lockout bucket instead.
# In-memory by design, same as lockout.py -- a restart simply means any
# in-flight mfa_pending tokens have to be re-issued by signing in again.
_mfa_jti_lock = threading.Lock()
_used_mfa_jti: dict[str, float] = {}  # jti -> token expiry (unix seconds)

_MFA_RESTART = "Start signing in again."


def _mfa_key(user_id: str) -> str:
    """Separate namespace from the password lockout in lockout.py, so a
    correct password followed by wrong codes locks the code step only."""
    return f"mfa:{user_id}"


def _decode_mfa_token(token: str) -> dict:
    """Validates an mfa_pending token WITHOUT spending it. Raises
    HTTPException(401) if it is invalid, expired, or already spent."""
    try:
        claims = security.decode_token(token, config.TOKEN_TYPE_MFA_PENDING)
    except security.TokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _MFA_RESTART)
    with _mfa_jti_lock:
        if claims["jti"] in _used_mfa_jti:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, _MFA_RESTART)
    return claims


def _spend_mfa_token(claims: dict) -> None:
    """Marks the token used. Atomic check-and-add, so two requests that
    both passed the code check can't both log in on one token. Also drops
    entries whose token has expired anyway, so the dict can't grow forever."""
    now = time.time()
    with _mfa_jti_lock:
        for jti in [j for j, exp in _used_mfa_jti.items() if exp <= now]:
            del _used_mfa_jti[jti]
        if claims["jti"] in _used_mfa_jti:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, _MFA_RESTART)
        _used_mfa_jti[claims["jti"]] = float(claims["exp"])


class TwoFactorSetupRequest(BaseModel):
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)


class TwoFactorVerifyRequest(BaseModel):
    code: str = Field(max_length=32)


class TwoFactorLoginRequest(BaseModel):
    mfa_token: str
    code: str = Field(max_length=32)


class BackupCodesRequest(BaseModel):
    code: str = Field(max_length=32)


class TwoFactorDisableRequest(BaseModel):
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)
    code: str = Field(max_length=32)


def _check_password(user: User, password: str) -> None:
    """Used by /setup and /disable: a stolen access token alone must not
    be enough to touch 2FA settings. Wrong attempts count toward the same
    password lockout as /auth/login."""
    key = store.normalize_email(user.email)
    wait = lockout.seconds_locked(key)
    if wait:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many failed attempts. Try again in {max(1, round(wait / 60))} minute(s).",
            headers={"Retry-After": str(wait)},
        )
    _, password_hash = store.get_credentials(user.email)
    if not security.verify_password(password_hash, password):
        lockout.record_failure(key)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect password.")
    lockout.reset(key)


def _check_totp_code(user: User, code: str, *, allow_backup: bool) -> bool:
    """Verifies a code against the mfa: lockout bucket. Returns True if a
    backup code was consumed (so callers can report remaining count),
    False for a normal TOTP code. Raises HTTPException on failure."""
    mfa_key = _mfa_key(user.user_id)
    wait = lockout.seconds_locked(mfa_key)
    if wait:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many failed attempts. Try again in {max(1, round(wait / 60))} minute(s).",
            headers={"Retry-After": str(wait)},
        )

    if allow_backup and totp.looks_like_backup_code(code):
        code_hash = totp.hash_backup_code(code)
        if store.use_backup_code(user.user_id, code_hash):
            lockout.reset(mfa_key)
            return True
        lockout.record_failure(mfa_key)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect code.")

    state = store.get_totp_state(user.user_id)
    if state is None or not state.secret:
        lockout.record_failure(mfa_key)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect code.")

    step = totp.verify_code(state.secret, code, state.last_step)
    if step is None:
        lockout.record_failure(mfa_key)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect code.")

    if not store.record_totp_step(user.user_id, step):
        # Another request spent this step between our check and now.
        lockout.record_failure(mfa_key)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect code.")
    lockout.reset(mfa_key)
    return False


@router.post("/2fa/setup")
def two_factor_setup(body: TwoFactorSetupRequest, user: User = Depends(get_current_user)):
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-factor authentication is already enabled.")
    _check_password(user, body.password)

    secret = totp.new_secret()
    store.set_pending_totp_secret(user.user_id, secret)
    uri = totp.provisioning_uri(secret, user.email)
    return {"secret": secret, "otpauth_uri": uri, "qr_code": totp.qr_data_uri(uri)}


@router.post("/2fa/verify")
def two_factor_verify(body: TwoFactorVerifyRequest, user: User = Depends(get_current_user)):
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-factor authentication is already enabled.")

    state = store.get_totp_state(user.user_id)
    if state is None or not state.secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Start setup first.")

    mfa_key = _mfa_key(user.user_id)
    wait = lockout.seconds_locked(mfa_key)
    if wait:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many failed attempts. Try again in {max(1, round(wait / 60))} minute(s).",
            headers={"Retry-After": str(wait)},
        )

    if totp.verify_code(state.secret, body.code, state.last_step) is None:
        lockout.record_failure(mfa_key)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect code.")
    lockout.reset(mfa_key)

    # Deliberately NOT store.record_totp_step(): confirming enrollment proves
    # the user holds the secret, but it must not burn the 30-second step,
    # or the very next sign-in (or "generate new backup codes") with the
    # fresh code from the same window is rejected as a replay. Replay
    # protection starts with the first real login, and an attacker who saw
    # this code would still need the password to use it.
    plain_codes, hashes = totp.generate_backup_codes()
    if not store.enable_totp(user.user_id, hashes):
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-factor authentication is already enabled.")
    activity_log.log_event(user, "2fa_enroll")
    return {"enabled": True, "backup_codes": plain_codes}


@router.post("/2fa/login")
def two_factor_login(body: TwoFactorLoginRequest):
    claims = _decode_mfa_token(body.mfa_token)
    user = store.get_user_by_id(claims["sub"])
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _MFA_RESTART)
    if not user.totp_enabled:
        # Account state changed underneath an in-flight mfa_pending token
        # (2FA was disabled elsewhere) -- treat as "start over", not a leak.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _MFA_RESTART)

    try:
        used_backup = _check_totp_code(user, body.code, allow_backup=True)
    except HTTPException:
        # _check_totp_code already raises 401/429 with the right message;
        # this only adds the log entry, using the same try/except shape as
        # the rest of the file rather than duplicating _check_totp_code's
        # checks here.
        activity_log.log_event(user, "mfa_login_failure")
        raise
    _spend_mfa_token(claims)  # only a correct code spends the token
    activity_log.log_event(user, "mfa_login_success", detail={"used_backup_code": used_backup})

    response = _login_success(user)
    if used_backup:
        response["backup_codes_remaining"] = store.count_unused_backup_codes(user.user_id)
    return response


@router.get("/2fa/status")
def two_factor_status(user: User = Depends(get_current_user)):
    remaining = store.count_unused_backup_codes(user.user_id) if user.totp_enabled else 0
    return {"enabled": user.totp_enabled, "backup_codes_remaining": remaining}


@router.post("/2fa/backup-codes")
def two_factor_backup_codes(body: BackupCodesRequest, user: User = Depends(get_current_user)):
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Two-factor authentication isn't enabled.")
    _check_totp_code(user, body.code, allow_backup=False)

    plain_codes, hashes = totp.generate_backup_codes()
    store.replace_backup_codes(user.user_id, hashes)
    return {"backup_codes": plain_codes}


@router.post("/2fa/disable")
def two_factor_disable(body: TwoFactorDisableRequest, user: User = Depends(get_current_user)):
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Two-factor authentication isn't enabled.")
    _check_password(user, body.password)
    _check_totp_code(user, body.code, allow_backup=True)

    store.disable_totp(user.user_id)
    activity_log.log_event(user, "2fa_disable")
    return {"enabled": False}
