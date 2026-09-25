"""
Phase 3 -- TOTP two-factor logic, deliberately kept free of HTTP and the
database so it can be unit tested without spinning up the API. routes.py
is the only caller with request/response knowledge; store.py is the only
module that persists any of this.
"""

import base64
import hashlib
import io
import secrets
import time
from typing import Optional

import pyotp
import qrcode

from . import config

# Unambiguous alphabet for backup codes: no 0/O or 1/l/I, so a code read
# off a printed page or a phone screen can't be misread digit-for-letter.
_BACKUP_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
_BACKUP_CODE_LEN = 10  # split 5-5 with a dash when displayed


# ---------- Secret + QR ----------

def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(
        name=email, issuer_name=config.TOTP_ISSUER
    )


def qr_data_uri(uri: str) -> str:
    """Renders the otpauth:// URI as a PNG and returns it as a data: URI,
    so the frontend just sets it as an <img src> with no image file ever
    touching disk."""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


# ---------- Code verification ----------

def _clean_code(code: str) -> str:
    return code.replace(" ", "")


def verify_code(secret: str, code: str, last_step: int, now: Optional[float] = None) -> Optional[int]:
    """Returns the matching 30-second time step if `code` is a valid,
    not-yet-used TOTP code for `secret`, else None.

    Checks the current step and TOTP_VALID_WINDOW steps either side (clock
    drift), but rejects any step <= last_step so a shoulder-surfed code
    can't be replayed within its own validity window.
    """
    code = _clean_code(code)
    if not code.isdigit() or len(code) != 6:
        return None

    now = time.time() if now is None else now
    totp = pyotp.TOTP(secret)
    current_step = int(now / totp.interval)

    for offset in range(-config.TOTP_VALID_WINDOW, config.TOTP_VALID_WINDOW + 1):
        step = current_step + offset
        if step <= last_step:
            continue
        candidate_time = step * totp.interval
        if totp.at(candidate_time) == code:
            return step
    return None


# ---------- Backup codes ----------

def _random_backup_code() -> str:
    raw = "".join(secrets.choice(_BACKUP_ALPHABET) for _ in range(_BACKUP_CODE_LEN))
    return f"{raw[:5]}-{raw[5:]}"


def generate_backup_codes() -> tuple[list[str], list[str]]:
    """Returns (plain_codes, hashes). Plain codes are shown to the user
    exactly once by the /verify and /backup-codes endpoints; only the
    hashes are ever stored."""
    plain = [_random_backup_code() for _ in range(config.BACKUP_CODE_COUNT)]
    hashes = [hash_backup_code(code) for code in plain]
    return plain, hashes


def normalize_backup_code(code: str) -> str:
    """Forgiving on purpose: uppercase, missing dash, or stray spaces all
    normalize to the same string the code was hashed from."""
    return code.strip().lower().replace(" ", "").replace("-", "")


def hash_backup_code(code: str) -> str:
    """SHA-256, not argon2: these are ~50 bits of random entropy (not a
    human-chosen password), so a fast hash is safe, and it lets the
    server look up a code with one indexed query instead of checking it
    against every stored hash with a slow KDF."""
    return hashlib.sha256(normalize_backup_code(code).encode("utf-8")).hexdigest()


def looks_like_backup_code(code: str) -> bool:
    """Tells the login route which check to run: a bare 6-digit string is
    a TOTP code, anything else offered at that prompt is a backup code."""
    return not _clean_code(code).isdigit()
