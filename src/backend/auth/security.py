"""
Password hashing (argon2) and token signing (JWT).

No database access here -- pure functions, easy to test.
"""

import time
import uuid

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from . import config

_hasher = PasswordHasher()

# Verified against when the email doesn't exist, so "unknown email" and
# "wrong password" take the same time and can't be told apart by timing.
_DUMMY_HASH = _hasher.hash("configguard-timing-equalizer")


class TokenError(Exception):
    """Any reason a token can't be used: bad signature, expired, wrong type."""


# ---------- Passwords ----------

def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def waste_verify_time(password: str) -> None:
    verify_password(_DUMMY_HASH, password)


def needs_rehash(password_hash: str) -> bool:
    """True if argon2's recommended parameters have moved on since this
    hash was made; the login route then re-hashes transparently."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return False


# ---------- Tokens ----------

def _encode(claims: dict, minutes: int) -> str:
    now = int(time.time())
    payload = {**claims, "iat": now, "exp": now + minutes * 60, "jti": uuid.uuid4().hex}
    return jwt.encode(payload, config.get_jwt_secret(), algorithm=config.JWT_ALGORITHM)


def create_access_token(user) -> str:
    """user is a store.User. org_id and role are included for the
    frontend's convenience; the backend re-reads both from the database."""
    return _encode(
        {"sub": user.user_id, "org_id": user.org_id, "role": user.role,
         "type": config.TOKEN_TYPE_ACCESS},
        config.ACCESS_TOKEN_MINUTES,
    )


def create_mfa_pending_token(user) -> str:
    """Issued between the password step and the TOTP step (Phase 3)."""
    return _encode({"sub": user.user_id, "type": config.TOKEN_TYPE_MFA_PENDING},
                   config.MFA_PENDING_TOKEN_MINUTES)


def decode_token(token: str, expected_type: str) -> dict:
    try:
        claims = jwt.decode(
            token,
            config.get_jwt_secret(),
            algorithms=[config.JWT_ALGORITHM],  # pinned: rejects alg=none and alg swaps
            options={"require": ["exp", "iat", "sub", "type"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid") from exc

    if claims.get("type") != expected_type:
        raise TokenError("wrong token type")
    return claims
