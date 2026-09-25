"""
Regression tests for bugs found while preparing Phase 4: 2FA retry and
replay handling, vote consensus, and input limits on the API.

Run from src/backend:  pytest auth/ -q
"""

import sqlite3
from pathlib import Path

import pyotp
import pytest

from auth.conftest import DEMO_PASSWORD

SAMPLE = (Path(__file__).resolve().parent.parent / "shared" / "sample_configs"
          / "cisco_mixed_unrecognized.txt").read_text()
LINE = "logging enable"


def _login(client, email):
    return client.post("/auth/login", json={"email": email, "password": DEMO_PASSWORD})


def _enroll(client, email):
    token = _login(client, email).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    secret = client.post("/auth/2fa/setup", json={"password": DEMO_PASSWORD}, headers=headers).json()["secret"]
    r = client.post("/auth/2fa/verify", json={"code": pyotp.TOTP(secret).now()}, headers=headers)
    assert r.status_code == 200, r.text
    return secret


def _upload(client, headers, text=SAMPLE, n=1):
    return client.post("/upload", headers=headers,
                       files=[("files", (f"r{i}.cfg", text.encode(), "text/plain")) for i in range(n)])


def _vote(client, headers, sid, field, value=True, line=LINE):
    return client.post("/confirm", headers=headers, json={
        "session_id": sid, "confirmations": [{"raw_line": line, "field": field, "value": value}]})


# ---------- 2FA ----------

def test_wrong_code_does_not_spend_the_mfa_token(client):
    """A typo must not force the user to re-enter their password: the same
    mfa_token still works for the corrected code."""
    secret = _enroll(client, "senior@alpha.demo")
    mfa_token = _login(client, "senior@alpha.demo").json()["mfa_token"]

    bad = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": "000000"})
    assert bad.status_code == 401 and bad.json()["detail"] == "Incorrect code."

    good = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": pyotp.TOTP(secret).now()})
    assert good.status_code == 200

    # ...but once it has worked, the token is spent.
    again = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": pyotp.TOTP(secret).now()})
    assert again.status_code == 401


def test_enrollment_does_not_burn_the_current_code(client):
    """Confirming enrollment with the code on screen, then signing in right
    away with the same code, works -- replay protection starts at first login."""
    secret = _enroll(client, "engineer@alpha.demo")
    mfa_token = _login(client, "engineer@alpha.demo").json()["mfa_token"]
    r = client.post("/auth/2fa/login", json={"mfa_token": mfa_token, "code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200


def test_record_totp_step_is_compare_and_set(api_mod):
    """Two requests carrying the same code must not both succeed."""
    from auth import store
    user, _ = store.get_credentials("engineer@alpha.demo")
    assert store.record_totp_step(user.user_id, 100) is True
    assert store.record_totp_step(user.user_id, 100) is False   # same step: replay
    assert store.record_totp_step(user.user_id, 99) is False    # older step
    assert store.record_totp_step(user.user_id, 101) is True


def test_enable_totp_twice_does_not_duplicate_backup_codes(api_mod):
    from auth import store, totp
    user, _ = store.get_credentials("engineer@alpha.demo")
    _, hashes = totp.generate_backup_codes()
    assert store.enable_totp(user.user_id, hashes) is True
    _, more = totp.generate_backup_codes()
    assert store.enable_totp(user.user_id, more) is False
    assert store.count_unused_backup_codes(user.user_id) == 8


def test_spent_mfa_tokens_are_pruned_after_expiry(api_mod):
    import time
    from auth import routes
    routes._used_mfa_jti.clear()
    routes._used_mfa_jti["old"] = time.time() - 10
    routes._spend_mfa_token({"jti": "new", "exp": time.time() + 300})
    assert set(routes._used_mfa_jti) == {"new"}


# ---------- Vote consensus ----------

def test_conflicting_votes_do_not_add_up(client, headers_for):
    """Admin says ssh_enabled, senior says telnet_enabled: 3 + 3 points from
    2 reviewers, but they agree on nothing, so nothing is promoted."""
    sid = _upload(client, headers_for("engineer@alpha.demo")).json()["results"][0]["session_id"]
    a = _vote(client, headers_for("admin@alpha.demo"), sid, "ssh_enabled").json()["review_results"][0]
    b = _vote(client, headers_for("senior@alpha.demo"), sid, "telnet_enabled").json()["review_results"][0]
    assert a["status"] == b["status"] == "recorded"
    assert b["total_points"] == 3 and b["num_reviewers"] == 1

    report = client.get("/review/report", headers=headers_for("viewer@alpha.demo")).json()
    assert report["promoted"] == []
    assert sorted(p["field"] for p in report["pending"]) == ["ssh_enabled", "telnet_enabled"]


def test_agreeing_votes_still_promote_even_after_a_conflict(client, headers_for):
    sid = _upload(client, headers_for("engineer@alpha.demo")).json()["results"][0]["session_id"]
    _vote(client, headers_for("engineer@alpha.demo"), sid, "telnet_enabled")           # 2, dissent
    _vote(client, headers_for("admin@alpha.demo"), sid, "logging_enabled")             # 3
    r = _vote(client, headers_for("senior@alpha.demo"), sid, "logging_enabled").json()  # 3 -> 6, 2 reviewers
    assert r["review_results"][0]["status"] == "promoted"
    assert r["config"]["logging_enabled"] is True


def test_same_field_different_value_does_not_combine(client, headers_for):
    sid = _upload(client, headers_for("engineer@alpha.demo")).json()["results"][0]["session_id"]
    line = "exec-timeout 10 0"
    a = _vote(client, headers_for("admin@alpha.demo"), sid, "session_timeout_seconds", 600, line)
    b = _vote(client, headers_for("senior@alpha.demo"), sid, "session_timeout_seconds", 60, line)
    assert b.json()["review_results"][0]["status"] == "recorded"
    assert a.json()["review_results"][0]["status"] == "recorded"


# ---------- /confirm input checks ----------

def test_unknown_field_is_rejected_and_nothing_is_recorded(client, headers_for):
    sid = _upload(client, headers_for("engineer@alpha.demo")).json()["results"][0]["session_id"]
    r = client.post("/confirm", headers=headers_for("admin@alpha.demo"), json={
        "session_id": sid,
        "confirmations": [
            {"raw_line": LINE, "field": "logging_enabled", "value": True},   # valid
            {"raw_line": "x", "field": "not_a_real_field", "value": 1},      # invalid
        ]})
    assert r.status_code == 400
    conn = sqlite3.connect("memory.db")
    votes = conn.execute("SELECT COUNT(*) FROM review_staging").fetchone()[0]
    conn.close()
    assert votes == 0   # the valid item was not applied either


def test_unclear_is_an_accepted_field(client, headers_for):
    sid = _upload(client, headers_for("engineer@alpha.demo")).json()["results"][0]["session_id"]
    assert _vote(client, headers_for("admin@alpha.demo"), sid, "unclear", None, "archive").status_code == 200


# ---------- /evaluate input checks ----------

def test_unknown_framework_is_a_400_not_an_empty_report(client, headers_for):
    h = headers_for("engineer@alpha.demo")
    sid = _upload(client, h).json()["results"][0]["session_id"]
    r = client.post(f"/evaluate/{sid}", headers=h, params={"frameworks": "CIS,BOGUS"})
    assert r.status_code == 400 and "BOGUS" in r.json()["detail"]


def test_blank_frameworks_defaults_to_cis(client, headers_for):
    h = headers_for("engineer@alpha.demo")
    sid = _upload(client, h).json()["results"][0]["session_id"]
    r = client.post(f"/evaluate/{sid}", headers=h, params={"frameworks": " , "})
    assert r.status_code == 200 and r.json()["findings"]


def test_framework_names_are_case_insensitive(client, headers_for):
    h = headers_for("engineer@alpha.demo")
    sid = _upload(client, h).json()["results"][0]["session_id"]
    assert client.post(f"/evaluate/{sid}", headers=h, params={"frameworks": "cis, nist"}).status_code == 200


# ---------- /upload limits ----------

def test_too_many_files_is_rejected(client, headers_for, api_mod):
    r = _upload(client, headers_for("engineer@alpha.demo"), text="hostname x\n", n=api_mod.MAX_UPLOAD_FILES + 1)
    assert r.status_code == 413


def test_oversized_file_is_reported_per_file(client, headers_for, api_mod, monkeypatch):
    monkeypatch.setattr(api_mod, "MAX_UPLOAD_BYTES", 10)
    before = len(api_mod.SESSIONS)
    r = _upload(client, headers_for("engineer@alpha.demo"))
    assert r.status_code == 200
    result = r.json()["results"][0]
    assert "error" in result and "session_id" not in result
    assert len(api_mod.SESSIONS) == before


def test_utf8_bom_does_not_change_detection(client, headers_for):
    h = headers_for("engineer@alpha.demo")
    plain = _upload(client, h).json()["results"][0]
    bom = _upload(client, h, text="\ufeff" + SAMPLE).json()["results"][0]
    assert bom["device"]["vendor"] == plain["device"]["vendor"]
    assert bom["config"] == plain["config"]
