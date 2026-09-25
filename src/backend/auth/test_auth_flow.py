"""
Phase 1 checkpoint tests: nothing works without signing in, and votes are
attributed to whoever is signed in.

Run from src/backend:  pytest auth/ -q
Each test gets a fresh, empty database in a temp folder -- your real
memory.db is never touched.
"""

import importlib
import sqlite3
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from auth.conftest import DEMO_PASSWORD, SECRET


def login(client, email, password=DEMO_PASSWORD):
    return client.post("/auth/login", json={"email": email, "password": password})


def auth_header(client, email, password=DEMO_PASSWORD):
    token = login(client, email, password).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------- Everything is locked without a token ----------

PROTECTED = [
    ("post", "/upload"),
    ("post", "/confirm"),
    ("post", "/evaluate/some-session"),
    ("get", "/report/some-session/pdf"),
    ("get", "/review/report"),
    ("get", "/auth/me"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_protected_endpoints_reject_anonymous(client, method, path):
    r = getattr(client, method)(path)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_health_stays_open(client):
    assert client.get("/health").status_code == 200


def test_valid_token_gets_past_auth(client):
    # 404 (unknown session), not 401, proves the token was accepted.
    r = client.post("/evaluate/does-not-exist", headers=auth_header(client, "engineer@alpha.demo"))
    assert r.status_code == 404


# ---------- Signup ----------

def test_signup_creates_new_org_with_caller_as_admin(client):
    r = client.post("/auth/signup", json={
        "email": "  Asha@Example.COM ", "password": "long-enough-pw",
        "name": "Asha", "org_name": "Acme Networks",
    })
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "asha@example.com"
    assert body["role"] == "admin"
    assert body["org_id"].startswith("org_") and body["org_id"] not in ("org_alpha", "org_beta")
    assert "password" not in str(body) and "hash" not in str(body)


def test_signup_ignores_client_supplied_org_id(client):
    r = client.post("/auth/signup", json={
        "email": "sneaky@example.com", "password": "long-enough-pw",
        "name": "Sneaky", "org_name": "Mine", "org_id": "org_alpha", "role": "admin",
    })
    assert r.status_code == 201
    assert r.json()["org_id"] != "org_alpha"


def test_signup_rejects_duplicate_email(client):
    payload = {"email": "dup@example.com", "password": "long-enough-pw", "name": "A", "org_name": "A"}
    assert client.post("/auth/signup", json=payload).status_code == 201
    assert client.post("/auth/signup", json={**payload, "email": "DUP@example.com"}).status_code == 409


@pytest.mark.parametrize("field,value", [
    ("password", "short"),
    ("email", "not-an-email"),
    ("name", "   "),
    ("org_name", ""),
])
def test_signup_validation(client, field, value):
    payload = {"email": "v@example.com", "password": "long-enough-pw", "name": "V", "org_name": "V"}
    payload[field] = value
    assert client.post("/auth/signup", json=payload).status_code == 422


def test_password_is_hashed_at_rest(client, api_mod):
    client.post("/auth/signup", json={
        "email": "hash@example.com", "password": "plain-text-pw", "name": "H", "org_name": "H"})
    conn = sqlite3.connect("memory.db")
    stored = conn.execute("SELECT password_hash FROM users WHERE email='hash@example.com'").fetchone()[0]
    assert stored.startswith("$argon2") and "plain-text-pw" not in stored


# ---------- Login ----------

def test_login_returns_token_and_user(client):
    r = login(client, "senior@beta.demo")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["token_type"] == "bearer"
    assert body["user"]["org_id"] == "org_beta" and body["user"]["role"] == "senior_engineer"

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.json() == body["user"]


def test_login_is_case_insensitive_on_email(client):
    assert login(client, "ADMIN@Alpha.Demo").status_code == 200


def test_wrong_password_and_unknown_email_look_identical(client):
    a = login(client, "admin@alpha.demo", "wrong-password")
    b = login(client, "nobody@alpha.demo", "wrong-password")
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_lockout_after_repeated_failures(client):
    for _ in range(5):
        assert login(client, "viewer@alpha.demo", "wrong-password").status_code == 401
    r = login(client, "viewer@alpha.demo")  # correct password, still locked
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0
    # Other accounts are unaffected.
    assert login(client, "viewer@beta.demo").status_code == 200


def test_success_resets_failure_count(client):
    for _ in range(4):
        login(client, "engineer@beta.demo", "wrong-password")
    assert login(client, "engineer@beta.demo").status_code == 200
    for _ in range(4):
        login(client, "engineer@beta.demo", "wrong-password")
    assert login(client, "engineer@beta.demo").status_code == 200


# ---------- Tokens that must be refused ----------

def _forge(claims, secret=SECRET):
    now = int(time.time())
    base = {"iat": now, "exp": now + 600, "type": "access", **claims}
    return {"Authorization": "Bearer " + jwt.encode(base, secret, algorithm="HS256")}


def _user_id(client, email):
    return login(client, email).json()["user"]["user_id"]


def test_token_signed_with_wrong_secret(client):
    uid = _user_id(client, "admin@alpha.demo")
    assert client.get("/auth/me", headers=_forge({"sub": uid}, secret="z" * 48)).status_code == 401


def test_expired_token(client):
    uid = _user_id(client, "admin@alpha.demo")
    old = int(time.time()) - 7200
    assert client.get("/auth/me", headers=_forge({"sub": uid, "iat": old, "exp": old + 60})).status_code == 401


def test_mfa_pending_token_is_not_an_access_token(client):
    uid = _user_id(client, "admin@alpha.demo")
    assert client.get("/auth/me", headers=_forge({"sub": uid, "type": "mfa_pending"})).status_code == 401


def test_unsigned_alg_none_token(client):
    uid = _user_id(client, "admin@alpha.demo")
    token = jwt.encode({"sub": uid, "type": "access", "iat": 1, "exp": 9999999999}, None, algorithm="none")
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_for_deleted_user(client):
    headers = auth_header(client, "viewer@beta.demo")
    sqlite3.connect("memory.db").execute("DELETE FROM users WHERE email='viewer@beta.demo'").connection.commit()
    assert client.get("/auth/me", headers=headers).status_code == 401


def test_role_comes_from_database_not_token(client):
    headers = auth_header(client, "viewer@alpha.demo")
    conn = sqlite3.connect("memory.db")
    conn.execute("UPDATE users SET role='engineer' WHERE email='viewer@alpha.demo'")
    conn.commit()
    assert client.get("/auth/me", headers=headers).json()["role"] == "engineer"


# ---------- /confirm uses the signed-in identity ----------

def _fake_session(api_mod):
    api_mod.SESSIONS["s1"] = {
        "org_id": "org_alpha", "owner_id": "someone",
        "filename": "r1.cfg", "raw_text": "", "device": {"vendor": "cisco"}, "config": {},
    }
    return "s1"


def test_confirm_attributes_vote_to_token_user_not_body(client, api_mod):
    sid = _fake_session(api_mod)
    headers = auth_header(client, "engineer@alpha.demo")
    me = client.get("/auth/me", headers=headers).json()

    r = client.post("/confirm", headers=headers, json={
        "session_id": sid,
        "confirmed_by": "senior@alpha.demo",  # spoof attempt, must be ignored
        "confirmations": [{"raw_line": "ip ssh version 2", "field": "ssh_enabled", "value": True}],
    })
    assert r.status_code == 200
    assert r.json()["review_results"][0]["status"] == "recorded"
    assert r.json()["review_results"][0]["total_points"] == 2  # engineer weight, not senior's 3

    voter = sqlite3.connect("memory.db").execute("SELECT submitted_by FROM review_staging").fetchone()[0]
    assert voter == me["user_id"]


def test_two_reviewers_reach_consensus(client, api_mod):
    sid = _fake_session(api_mod)
    line = {"raw_line": "service password-encryption", "field": "password_encryption", "value": True}
    body = {"session_id": sid, "confirmations": [line]}

    first = client.post("/confirm", headers=auth_header(client, "admin@alpha.demo"), json=body)
    assert first.json()["review_results"][0]["status"] == "recorded"
    second = client.post("/confirm", headers=auth_header(client, "senior@alpha.demo"), json=body)
    assert second.json()["review_results"][0]["status"] == "promoted"
    assert second.json()["config"]["password_encryption"] is True


def test_viewer_cannot_vote(client, api_mod):
    sid = _fake_session(api_mod)
    r = client.post("/confirm", headers=auth_header(client, "viewer@alpha.demo"), json={
        "session_id": sid,
        "confirmations": [{"raw_line": "x", "field": "unclear", "value": None}],
    })
    assert r.status_code == 403


# ---------- Migration from the pre-auth users table ----------

def test_old_users_table_is_replaced(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.setenv("DEMO_PASSWORD", DEMO_PASSWORD)
    monkeypatch.setenv("GROQ_API_KEY", "")
    conn = sqlite3.connect("memory.db")
    conn.execute("CREATE TABLE users (user_id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL)")
    conn.execute("INSERT INTO users VALUES ('alice', 'Alice', 'senior_engineer')")
    conn.commit()
    conn.close()

    import api
    importlib.reload(api)

    cols = {r[1] for r in sqlite3.connect("memory.db").execute("PRAGMA table_info(users)")}
    assert {"email", "password_hash", "org_id"} <= cols
    assert login(TestClient(api.app), "admin@alpha.demo").status_code == 200
