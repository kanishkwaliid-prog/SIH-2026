"""
Brute-force protection: MAX_FAILED_ATTEMPTS failures within
LOCKOUT_MINUTES lock that account for LOCKOUT_MINUTES.

Keyed by normalised email, and counted even for emails that don't exist,
so the lockout behaviour doesn't reveal which accounts are real.

In-memory by design (Phase 0, decision 5): a restart clears lockouts,
which is harmless. Phase 3 reuses this for TOTP codes.
"""

import threading
import time

from . import config

_lock = threading.Lock()
_failures: dict[str, list[float]] = {}
_locked_until: dict[str, float] = {}


def _window() -> float:
    return config.LOCKOUT_MINUTES * 60


def seconds_locked(key: str) -> int:
    """0 if the key may try again, otherwise seconds until it can."""
    with _lock:
        until = _locked_until.get(key, 0)
        remaining = until - time.time()
        if remaining <= 0:
            _locked_until.pop(key, None)
            return 0
        return int(remaining) + 1


def record_failure(key: str) -> None:
    now = time.time()
    with _lock:
        recent = [t for t in _failures.get(key, []) if now - t < _window()]
        recent.append(now)
        if len(recent) >= config.MAX_FAILED_ATTEMPTS:
            _locked_until[key] = now + _window()
            _failures.pop(key, None)
        else:
            _failures[key] = recent


def reset(key: str) -> None:
    with _lock:
        _failures.pop(key, None)
        _locked_until.pop(key, None)


def clear_all() -> None:
    """Tests only."""
    with _lock:
        _failures.clear()
        _locked_until.clear()
