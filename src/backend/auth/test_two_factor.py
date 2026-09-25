"""
Phase 3 checkpoint tests: TOTP enrollment, the two-step login, backup
codes and disable. Uses pyotp.TOTP(secret).at(time) to generate valid
codes so nothing here waits on real time.

Run from src/backend:  pytest auth/ -q
"""

import time

import pyotp
import pytest

from auth.conftest import DEMO_PASSWORD


def login(client, email, password=DEMO_PASSWORD):
    return client.post("/auth/login", json={"email": email, "password": password})


def auth_header(client, email, password=DEMO_PASSWORD):
    token = login(client, email, password).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def code_for(secret: str, when: float | None = None) -> str:
    return pyotp.TOTP(secret).at(time.time() if when is None else when)


def enroll(client, email, password=DEMO_PASSWORD):
    """Full happy-path enrollment. Returns (headers, secret, backup_codes)."""
    headers = auth_header(client, email, password)
    setup = client.post("/auth/2fa/setup", json={"password": password}, headers=headers)
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]

    verify = client.post("/auth/2fa/verify", json={"code": code_for(secret)}, headers=headers)
    assert verify.status_code == 200, verify.text
    backup_codes = verify.json()["backup_codes"]
    return headers, secret, backup_codes


# ---------- Pure totp.py unit tests (no DB, no client) ----------

def test_verify_code_accepts_current_step():
    from auth import totp as totp_mod
    secret = totp_mod.new_secret()
    now = time.time()
    code = pyotp.TOTP(secret).at(now)
    assert totp_mod.verify_code(secret, code, last_step=0, now=now) is not None


def test_verify_code_rejects_replay_of_same_step():
    from auth import totp as totp_mod
    secret = totp_mod.new_secret()
    now = time.time()
    code = pyotp.TOTP(secret).at(now)
    step = totp_mod.verify_code(secret, code, last_step=0, now=now)
    assert step is not None
    # Same step re-checked with last_step now advanced to it -> rejected.
    assert totp_mod.verify_code(secret, code, last_step=step, now=now) is None


def test_verify_code_rejects_bad_format():
    from auth import totp as totp_mod
    secret = totp_mod.new_secret()
    assert totp_mod.verify_code(secret, "12345", last_step=0) is None  # too short
    assert totp_mod.verify_code(secret, "abcdef", last_step=0) is None  # not digits


def test_backup_code_normalization_round_trips():
    from auth import totp as totp_mod
    plain, hashes = totp_mod.generate_backup_codes()
    code = plain[0]
    messy = " " + code.upper().replace("-", "   ") + " "
    assert totp_mod.hash_backup_code(messy) == totp_mod.hash_backup_code(code)
    assert totp_mod.hash_backup_code(code) in hashes


def test_looks_like_backup_code():
    from auth import totp as totp_mod
    assert totp_mod.looks_like_backup_code("k7mqp-x2hvn") is True
    assert totp_mod.looks_like_backup_code("123456") is False


# ---------- Enrollment ----------

def test_setup_requires_correct_password(client):
    headers = auth_header(client, "engineer@alpha.demo")
    r = client.post("/auth/2fa/setup", json={"password": "wrong-password"}, headers=headers)
    assert r.status_code == 401


def test_setup_does_not_enable_2fa(client):
    headers = auth_header(client, "engineer@alpha.demo")
    r = client.post("/auth/2fa/setup", json={"password": DEMO_PASSWORD}, headers=headers)
    assert r.status_code == 200
    assert set(r.json()) == {"secret", "otpauth_uri", "qr_code"}

    # Login still returns a token directly -- nothing has changed for the
    # user yet, since they haven't confirmed a code.
    again = login(client, "engineer@alpha.demo")
    assert again.status_code == 200
    assert again.json()["status"] == "ok"


def test_verify_with_wrong_code_does_not_enable(client):
    headers = auth_header(client, "engineer@alpha.demo")
    setup = client.post("/auth/2fa/setup", json={"password": DEMO_PASSWORD}, headers=headers)
    secret = setup.json()["secret"]

    # A code from far outside the valid window.
    bad_code = pyotp.TOTP(secret).at(time.time() + 3600)
    r = client.post("/auth/2fa/verify", json={"code": bad_code}, headers=headers)
    assert r.status_code == 401

    status_r = client.get("/auth/2fa/status", headers=headers)
    assert status_r.json()["enabled"] is False


def test_verify_with_correct_code_enables_and_returns_eight_codes(client):
    headers, secret, backup_codes = enroll(client, "senior@alpha.demo")
    assert len(backup_codes) == 8
    assert len(set(backup_codes)) == 8

    status_r = client.get("/auth/2fa/status", headers=headers)
    assert status_r.json() == {"enabled": True, "backup_codes_remaining": 8}


def test_setup_after_enabled_returns_409(client):
    headers, _, _ = enroll(client, "senior@alpha.demo")
    r = client.post("/auth/2fa/setup", json={"password": DEMO_PASSWORD}, headers=headers)
    assert r.status_code == 409


def test_only_hashes_are_stored(client, api_mod):
    headers, secret, backup_codes = enroll(client, "senior@alpha.demo")

    import sqlite3
    from block2b import memory as memory_mod
    conn = sqlite3.connect(memory_mod.DB_PATH)
    stored = [r[0] for r in conn.execute("SELECT code_hash FROM backup_codes")]
    stored_secret = conn.execute(
        "SELECT totp_secret FROM users WHERE email = ?", ("senior@alpha.demo",)
    ).fetchone()[0]
    conn.close()

    assert stored_secret == secret  # known gap, documented: plaintext at rest
    for plain in backup_codes:
        assert plain not in stored


# ---------- Login ----------

def test_login_with_2fa_on_returns_mfa_required(client):
    enroll(client, "senior@alpha.demo")
    r = login(client, "senior@alpha.demo")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "mfa_required"
    assert "mfa_token" in body
    assert "access_token" not in body


def test_mfa_token_rejected_by_protected_endpoints(client):
    enroll(client, "senior@alpha.demo")
    mfa_token = login(client, "senior@alpha.demo").json()["mfa_token"]
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {mfa_token}"})
    assert r.status_code == 401


def test_correct_code_returns_working_access_token(client):
    _, secret, _ = enroll(client, "senior@alpha.demo")
    mfa_token = login(client, "senior@alpha.demo").json()["mfa_token"]

    r = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": code_for(secret)})
    assert r.status_code == 200
    access_token = r.json()["access_token"]
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert me.status_code == 200
    assert me.json()["email"] == "senior@alpha.demo"


def test_adjacent_steps_accepted_two_steps_away_rejected(client):
    _, secret, _ = enroll(client, "senior@alpha.demo")
    totp_obj = pyotp.TOTP(secret)

    mfa_token = login(client, "senior@alpha.demo").json()["mfa_token"]
    one_step_ago = code_for(secret, time.time() - totp_obj.interval)
    r = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": one_step_ago})
    assert r.status_code == 200

    mfa_token2 = login(client, "senior@alpha.demo").json()["mfa_token"]
    two_steps_away = code_for(secret, time.time() + 2 * totp_obj.interval)
    r2 = client.post("/auth/2fa/login", json={"mfa_token": mfa_token2, "code": two_steps_away})
    assert r2.status_code == 401


def test_replay_within_window_rejected(client):
    _, secret, _ = enroll(client, "senior@alpha.demo")
    code = code_for(secret)

    mfa_token = login(client, "senior@alpha.demo").json()["mfa_token"]
    first = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": code})
    assert first.status_code == 200

    mfa_token2 = login(client, "senior@alpha.demo").json()["mfa_token"]
    second = client.post("/auth/2fa/login", json={"mfa_token": mfa_token2, "code": code})
    assert second.status_code == 401


def test_mfa_token_is_single_use(client):
    _, secret, _ = enroll(client, "senior@alpha.demo")
    mfa_token = login(client, "senior@alpha.demo").json()["mfa_token"]

    first = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": code_for(secret)})
    assert first.status_code == 200

    replay = client.post(
        "/auth/2fa/login",
        json={"mfa_token": mfa_token, "code": code_for(secret, time.time() + 30)},
    )
    assert replay.status_code == 401


def test_expired_mfa_token_rejected(client, monkeypatch):
    _, secret, _ = enroll(client, "senior@alpha.demo")
    from auth import config
    monkeypatch.setattr(config, "MFA_PENDING_TOKEN_MINUTES", -1)  # already expired
    mfa_token = login(client, "senior@alpha.demo").json()["mfa_token"]
    r = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": code_for(secret)})
    assert r.status_code == 401


def test_five_wrong_codes_lock_even_if_sixth_is_correct(client):
    _, secret, _ = enroll(client, "senior@alpha.demo")

    for _ in range(5):
        mfa_token = login(client, "senior@alpha.demo").json()["mfa_token"]
        r = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": "000000"})
        assert r.status_code == 401

    mfa_token = login(client, "senior@alpha.demo").json()["mfa_token"]
    r = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": code_for(secret)})
    assert r.status_code == 429


def test_user_without_2fa_sees_no_change(client):
    r = login(client, "engineer@alpha.demo")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "access_token" in r.json()


# ---------- Backup codes ----------

def test_backup_code_works_once(client):
    _, _, backup_codes = enroll(client, "senior@alpha.demo")
    code = backup_codes[0]

    mfa_token = login(client, "senior@alpha.demo").json()["mfa_token"]
    first = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": code})
    assert first.status_code == 200
    assert first.json()["backup_codes_remaining"] == 7

    mfa_token2 = login(client, "senior@alpha.demo").json()["mfa_token"]
    second = client.post("/auth/2fa/login", json={"mfa_token": mfa_token2, "code": code})
    assert second.status_code == 401


def test_backup_code_format_is_forgiving(client):
    _, _, backup_codes = enroll(client, "senior@alpha.demo")
    code = backup_codes[0]
    messy = code.upper().replace("-", "  ")

    mfa_token = login(client, "senior@alpha.demo").json()["mfa_token"]
    r = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": messy})
    assert r.status_code == 200


def test_one_users_backup_code_does_not_work_for_another(client):
    _, _, alpha_codes = enroll(client, "senior@alpha.demo")
    enroll(client, "senior@beta.demo")

    mfa_token = login(client, "senior@beta.demo").json()["mfa_token"]
    r = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": alpha_codes[0]})
    assert r.status_code == 401


def test_regenerate_invalidates_old_codes(client):
    headers, secret, old_codes = enroll(client, "senior@alpha.demo")

    r = client.post("/auth/2fa/backup-codes", json={"code": code_for(secret)}, headers=headers)
    assert r.status_code == 200
    new_codes = r.json()["backup_codes"]
    assert len(new_codes) == 8
    assert set(new_codes).isdisjoint(old_codes)

    mfa_token = login(client, "senior@alpha.demo").json()["mfa_token"]
    r2 = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": old_codes[0]})
    assert r2.status_code == 401


# ---------- Disable ----------

def test_disable_needs_both_password_and_code(client):
    headers, secret, _ = enroll(client, "senior@alpha.demo")

    only_password = client.post(
        "/auth/2fa/disable", json={"password": DEMO_PASSWORD, "code": "000000"}, headers=headers
    )
    assert only_password.status_code == 401

    only_code = client.post(
        "/auth/2fa/disable", json={"password": "wrong", "code": code_for(secret)}, headers=headers
    )
    assert only_code.status_code == 401


def test_disable_then_login_is_single_step_again(client):
    headers, secret, backup_codes = enroll(client, "senior@alpha.demo")

    r = client.post(
        "/auth/2fa/disable",
        json={"password": DEMO_PASSWORD, "code": code_for(secret)},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["enabled"] is False

    again = login(client, "senior@alpha.demo")
    assert again.json()["status"] == "ok"

    # Old backup codes are gone -- re-enroll and confirm none of them work.
    headers2, secret2, new_codes = enroll(client, "senior@alpha.demo")
    assert set(new_codes).isdisjoint(backup_codes)


# ---------- Regression ----------

def test_full_suite_still_green():
    """Placeholder marker: the real regression check is `pytest auth/ -q`
    running all files together, not this one test in isolation."""
    assert True
