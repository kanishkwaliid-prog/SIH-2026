"""
Phase 4 checkpoint: roles are enforced, not just documented.

The permission matrix lives in auth/config.py (ROLE_PERMISSIONS); these
tests hit the real endpoints as each demo role and check the outcome
matches it. A 403 must come back BEFORE anything else happens, so a
forbidden caller can't learn which sessions exist.

Run from src/backend:  pytest auth/ -q
"""

import sqlite3
from pathlib import Path

import pytest
from fastapi.routing import APIRoute

from auth.conftest import DEMO_PASSWORD

SAMPLE = (Path(__file__).resolve().parent.parent / "shared" / "sample_configs"
          / "cisco_mixed_unrecognized.txt").read_text()

ROLES = ["admin", "senior", "engineer", "viewer"]
CAN_UPLOAD = {"admin", "senior", "engineer"}


def email(role, org="alpha"):
    return f"{role}@{org}.demo"


def upload_files(client, headers, text=SAMPLE):
    return client.post("/upload", headers=headers,
                       files=[("files", ("router.cfg", text.encode(), "text/plain"))])


@pytest.fixture
def session_id(client, headers_for):
    r = upload_files(client, headers_for(email("engineer")))
    assert r.status_code == 200, r.text
    return r.json()["results"][0]["session_id"]


# ---------- Every route declares its permission ----------

# Routes that are deliberately not gated by a role: either public, or
# self-service for any signed-in user (their own profile / own 2FA).
OPEN_ROUTES = {
    "/", "/health",
    "/auth/signup", "/auth/login", "/auth/2fa/login",
    "/auth/me", "/auth/2fa/setup", "/auth/2fa/verify", "/auth/2fa/status",
    "/auth/2fa/backup-codes", "/auth/2fa/disable",
}


def _declared_permissions(dependant):
    found = set()
    for dep in dependant.dependencies:
        perm = getattr(dep.call, "required_permission", None)
        if perm is not None:
            found.add(perm)
        found |= _declared_permissions(dep)
    return found


def test_every_route_declares_a_permission(api_mod):
    """Fails if someone adds an endpoint and forgets require_permission --
    the exact mistake that left every endpoint open to every role."""
    for route in api_mod.app.routes:
        if not isinstance(route, APIRoute) or route.path in OPEN_ROUTES:
            continue
        assert _declared_permissions(route.dependant), (
            f"{route.path} has no require_permission(...). Add one, or list it in "
            f"OPEN_ROUTES if it is deliberately open."
        )


# ---------- Analyst actions ----------

@pytest.mark.parametrize("role", ROLES)
def test_upload_permission_matrix(client, headers_for, role):
    r = upload_files(client, headers_for(email(role)))
    assert r.status_code == (200 if role in CAN_UPLOAD else 403), r.text


def test_viewer_upload_creates_no_session(client, headers_for, api_mod):
    before = len(api_mod.SESSIONS)
    assert upload_files(client, headers_for(email("viewer"))).status_code == 403
    assert len(api_mod.SESSIONS) == before


@pytest.mark.parametrize("role", ROLES)
def test_evaluate_permission_matrix(client, headers_for, session_id, role):
    r = client.post(f"/evaluate/{session_id}", headers=headers_for(email(role)))
    assert r.status_code == (200 if role in CAN_UPLOAD else 403), r.text


@pytest.mark.parametrize("role", ROLES)
def test_confirm_permission_matrix(client, headers_for, session_id, role):
    r = client.post("/confirm", headers=headers_for(email(role)), json={
        "session_id": session_id,
        "confirmations": [{"raw_line": "logging enable", "field": "logging_enabled", "value": True}],
    })
    assert r.status_code == (200 if role in CAN_UPLOAD else 403), r.text


def test_forbidden_caller_learns_nothing_about_sessions(client, headers_for, session_id):
    """A viewer gets the same 403 for a real and a made-up session id, so
    the permission check can't be used to probe which ids exist."""
    viewer = headers_for(email("viewer"))
    real = client.post(f"/evaluate/{session_id}", headers=viewer)
    fake = client.post("/evaluate/00000000-0000-4000-8000-000000000000", headers=viewer)
    assert (real.status_code, real.json()) == (fake.status_code, fake.json()) == (403, real.json())


# ---------- Viewer keeps read access ----------

@pytest.mark.parametrize("role", ROLES)
def test_everyone_can_read_the_review_report(client, headers_for, role):
    assert client.get("/review/report", headers=headers_for(email(role))).status_code == 200


def test_viewer_can_reach_pdf_endpoint(client, headers_for, session_id):
    """Permission is granted: the 400 is 'not evaluated yet', not a 403."""
    r = client.get(f"/report/{session_id}/pdf", headers=headers_for(email("viewer")))
    assert r.status_code == 400


# ---------- Role changes take effect immediately ----------

def test_demotion_applies_to_an_existing_token(client, headers_for):
    headers = headers_for(email("engineer"))  # token issued while an engineer
    assert upload_files(client, headers).status_code == 200

    conn = sqlite3.connect("memory.db")
    conn.execute("UPDATE users SET role = 'viewer' WHERE email = ?", (email("engineer"),))
    conn.commit()
    conn.close()

    assert upload_files(client, headers).status_code == 403


def test_tampered_role_claim_in_token_is_ignored(client, headers_for):
    """The JWT carries a role for the UI's convenience only; a viewer
    can't upload by holding a token that says otherwise."""
    import time
    import jwt
    from auth.conftest import SECRET
    viewer = client.post("/auth/login", json={"email": email("viewer"), "password": DEMO_PASSWORD}).json()
    now = int(time.time())
    forged = jwt.encode({"sub": viewer["user"]["user_id"], "type": "access", "role": "admin",
                         "org_id": "org_alpha", "iat": now, "exp": now + 600}, SECRET, algorithm="HS256")
    r = upload_files(client, {"Authorization": f"Bearer {forged}"})
    assert r.status_code == 403


# ---------- Admin: member management ----------

def test_only_admin_can_use_admin_endpoints(client, headers_for):
    for role in ROLES:
        h = headers_for(email(role))
        assert client.get("/admin/users", headers=h).status_code == (200 if role == "admin" else 403)
        assert client.post("/admin/users", headers=h, json={
            "email": f"x-{role}@alpha.demo", "name": "X", "password": "long-enough-pw",
        }).status_code == (201 if role == "admin" else 403)


def test_admin_endpoints_reject_anonymous(client):
    assert client.get("/admin/users").status_code == 401


def test_list_members_is_scoped_to_own_org(client, headers_for):
    users = client.get("/admin/users", headers=headers_for(email("admin"))).json()["users"]
    assert {u["email"] for u in users} == {email(r) for r in ROLES}
    assert all(u["org_id"] == "org_alpha" for u in users)
    assert "password" not in str(users) and "hash" not in str(users)


def test_add_member_defaults_to_viewer_in_admins_org(client, headers_for):
    admin = headers_for(email("admin"))
    r = client.post("/admin/users", headers=admin, json={
        "email": "New.Person@Alpha.demo", "name": "New Person", "password": "long-enough-pw",
        # Client-supplied org must be ignored.
        "org_id": "org_beta",
    })
    assert r.status_code == 201
    body = r.json()
    assert body["role"] == "viewer" and body["org_id"] == "org_alpha"
    assert body["email"] == "new.person@alpha.demo"

    # They can sign in, but can't upload.
    h = headers_for("new.person@alpha.demo", "long-enough-pw")
    assert upload_files(client, h).status_code == 403


def test_add_member_with_explicit_role(client, headers_for):
    r = client.post("/admin/users", headers=headers_for(email("admin")), json={
        "email": "eng2@alpha.demo", "name": "Eng Two", "password": "long-enough-pw", "role": "engineer"})
    assert r.status_code == 201 and r.json()["role"] == "engineer"
    assert upload_files(client, headers_for("eng2@alpha.demo", "long-enough-pw")).status_code == 200


@pytest.mark.parametrize("payload,code", [
    ({"email": "viewer@alpha.demo", "name": "Dup", "password": "long-enough-pw"}, 409),   # duplicate
    ({"email": "viewer@beta.demo", "name": "Dup", "password": "long-enough-pw"}, 409),    # exists in other org
    ({"email": "bad", "name": "X", "password": "long-enough-pw"}, 422),
    ({"email": "a@b.co", "name": "X", "password": "short"}, 422),
    ({"email": "a@b.co", "name": "X", "password": "long-enough-pw", "role": "superuser"}, 422),
])
def test_add_member_validation(client, headers_for, payload, code):
    assert client.post("/admin/users", headers=headers_for(email("admin")), json=payload).status_code == code


def _user_id(client, headers_for, addr):
    return client.post("/auth/login", json={"email": addr, "password": DEMO_PASSWORD}).json()["user"]["user_id"]


def test_admin_can_change_a_role(client, headers_for):
    uid = _user_id(client, headers_for, email("viewer"))
    r = client.patch(f"/admin/users/{uid}/role", headers=headers_for(email("admin")), json={"role": "engineer"})
    assert r.status_code == 200 and r.json()["role"] == "engineer"
    assert upload_files(client, headers_for(email("viewer"))).status_code == 200


def test_invalid_role_is_rejected(client, headers_for):
    uid = _user_id(client, headers_for, email("viewer"))
    r = client.patch(f"/admin/users/{uid}/role", headers=headers_for(email("admin")), json={"role": "root"})
    assert r.status_code == 422


def test_admin_cannot_touch_another_orgs_member(client, headers_for):
    beta_viewer = _user_id(client, headers_for, email("viewer", "beta"))
    admin = headers_for(email("admin"))
    real = client.patch(f"/admin/users/{beta_viewer}/role", headers=admin, json={"role": "admin"})
    fake = client.patch("/admin/users/usr_doesnotexist/role", headers=admin, json={"role": "admin"})
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json()

    reset = client.post(f"/admin/users/{beta_viewer}/reset-2fa", headers=admin)
    assert reset.status_code == 404

    # ...and beta's viewer really is unchanged.
    conn = sqlite3.connect("memory.db")
    role = conn.execute("SELECT role FROM users WHERE user_id = ?", (beta_viewer,)).fetchone()[0]
    conn.close()
    assert role == "viewer"


def test_cannot_demote_the_last_admin(client, headers_for):
    admin = headers_for(email("admin"))
    uid = _user_id(client, headers_for, email("admin"))
    r = client.patch(f"/admin/users/{uid}/role", headers=admin, json={"role": "viewer"})
    assert r.status_code == 409
    assert client.get("/admin/users", headers=admin).status_code == 200  # still an admin


def test_admin_can_be_demoted_when_another_admin_exists(client, headers_for):
    admin = headers_for(email("admin"))
    second = client.post("/admin/users", headers=admin, json={
        "email": "admin2@alpha.demo", "name": "Admin Two", "password": "long-enough-pw", "role": "admin"}).json()
    uid = _user_id(client, headers_for, email("admin"))
    r = client.patch(f"/admin/users/{uid}/role", headers=admin, json={"role": "engineer"})
    assert r.status_code == 200
    assert second["role"] == "admin"


# ---------- Admin: reset a member's 2FA ----------

def _enroll(client, headers_for, addr):
    import pyotp
    h = headers_for(addr)
    secret = client.post("/auth/2fa/setup", json={"password": DEMO_PASSWORD}, headers=h).json()["secret"]
    ok = client.post("/auth/2fa/verify", json={"code": pyotp.TOTP(secret).now()}, headers=h)
    assert ok.status_code == 200, ok.text
    return secret


def test_admin_resets_member_2fa(client, headers_for):
    _enroll(client, headers_for, email("engineer"))
    assert client.post("/auth/login", json={"email": email("engineer"), "password": DEMO_PASSWORD}
                       ).json()["status"] == "mfa_required"

    uid = _user_id_no_login_needed(client, headers_for)
    r = client.post(f"/admin/users/{uid}/reset-2fa", headers=headers_for(email("admin")))
    assert r.status_code == 200 and r.json()["totp_enabled"] is False

    again = client.post("/auth/login", json={"email": email("engineer"), "password": DEMO_PASSWORD}).json()
    assert again["status"] == "ok"

    conn = sqlite3.connect("memory.db")
    left = conn.execute("SELECT COUNT(*) FROM backup_codes").fetchone()[0]
    secret = conn.execute("SELECT totp_secret FROM users WHERE email = ?", (email("engineer"),)).fetchone()[0]
    conn.close()
    assert left == 0 and secret is None


def _user_id_no_login_needed(client, headers_for):
    """The engineer has 2FA on now, so /auth/login no longer returns a user;
    read the id from the admin's member list instead."""
    users = client.get("/admin/users", headers=headers_for(email("admin"))).json()["users"]
    return next(u["user_id"] for u in users if u["email"] == email("engineer"))


def test_admin_cannot_reset_their_own_2fa_this_way(client, headers_for):
    uid = _user_id(client, headers_for, email("admin"))
    r = client.post(f"/admin/users/{uid}/reset-2fa", headers=headers_for(email("admin")))
    assert r.status_code == 400


def test_non_admin_cannot_reset_2fa(client, headers_for):
    uid = _user_id(client, headers_for, email("viewer"))
    r = client.post(f"/admin/users/{uid}/reset-2fa", headers=headers_for(email("senior")))
    assert r.status_code == 403
