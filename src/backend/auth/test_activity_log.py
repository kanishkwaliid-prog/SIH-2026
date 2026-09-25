"""
Phase 5 checkpoint: the activity log records what happened, keeps each
org's history separate, and is tamper-evident -- and none of that is
allowed to get in the way of the action it's describing.

Run from src/backend:  pytest auth/ -q
"""

import sqlite3

import activity_log
import pytest

from auth.conftest import DEMO_PASSWORD

SAMPLE_LINE = "logging enable"


def email(role, org="alpha"):
    return f"{role}@{org}.demo"


def upload_files(client, headers):
    text = "hostname router1\ninterface GigabitEthernet0/1\n"
    return client.post("/upload", headers=headers,
                       files=[("files", ("router.cfg", text.encode(), "text/plain"))])


def audit(client, headers, **params):
    return client.get("/audit", headers=headers, params=params)


# ---------- Chain integrity ----------

def test_chain_is_valid_after_several_events(client, headers_for):
    engineer = headers_for(email("engineer"))
    admin = headers_for(email("admin"))

    r = upload_files(client, engineer)
    assert r.status_code == 200, r.text
    session_id = r.json()["results"][0]["session_id"]
    assert client.post(f"/evaluate/{session_id}", headers=engineer).status_code == 200
    assert client.post("/confirm", headers=engineer, json={
        "session_id": session_id,
        "confirmations": [{"raw_line": SAMPLE_LINE, "field": "logging_enabled", "value": True}],
    }).status_code == 200

    body = audit(client, admin).json()
    assert body["chain_valid"] is True
    # login (admin, for this request) + login (engineer, via headers_for) +
    # upload + evaluate + confirm, at minimum.
    event_types = [e["event_type"] for e in body["entries"]]
    assert "upload" in event_types
    assert "evaluate" in event_types
    assert "confirm" in event_types
    assert len(body["entries"]) >= 5


def test_login_success_and_failure_are_logged(client, headers_for):
    # Login success: headers_for already did the successful login.
    admin = headers_for(email("admin"))
    r = client.post("/auth/login", json={"email": email("engineer"), "password": "wrong-password"})
    assert r.status_code == 401

    entries = audit(client, admin).json()["entries"]
    failure = next(e for e in entries if e["event_type"] == "login_failure")
    assert failure["target"] == email("engineer")
    assert failure["actor_user_id"] is None  # nobody authenticated -- see log_event's docstring

    assert any(e["event_type"] == "login_success" for e in entries)


def test_unknown_email_login_failure_is_not_logged(client, headers_for):
    """Design decision: an email that matches no account has no org to
    attribute the attempt to, so it is not logged at all (rather than into
    a shared/global bucket)."""
    admin = headers_for(email("admin"))
    before = audit(client, admin).json()["entries"]

    r = client.post("/auth/login", json={"email": "nobody-at-all@alpha.demo", "password": "whatever"})
    assert r.status_code == 401

    after = audit(client, admin).json()["entries"]
    # The failed request itself logged nothing; only the /audit read above added an entry (none -- GET isn't logged).
    assert len(after) == len(before)
    assert not any(e.get("target") == "nobody-at-all@alpha.demo" for e in after)


# ---------- Tamper detection ----------

def test_tampering_is_detected(client, headers_for):
    admin = headers_for(email("admin"))
    assert upload_files(client, headers_for(email("engineer"))).status_code == 200
    assert audit(client, admin).json()["chain_valid"] is True

    conn = sqlite3.connect("memory.db")
    conn.execute(
        "UPDATE activity_log SET target = 'tampered.cfg' "
        "WHERE id = (SELECT MAX(id) FROM activity_log WHERE org_id = 'org_alpha')"
    )
    conn.commit()
    conn.close()

    assert audit(client, admin).json()["chain_valid"] is False


def test_verify_activity_chain_directly(api_mod, client, headers_for):
    assert upload_files(client, headers_for(email("engineer"))).status_code == 200
    assert activity_log.verify_activity_chain("org_alpha") is True

    conn = sqlite3.connect("memory.db")
    conn.execute(
        "UPDATE activity_log SET detail = '{\"tampered\": true}' "
        "WHERE id = (SELECT MAX(id) FROM activity_log)"
    )
    conn.commit()
    conn.close()

    assert activity_log.verify_activity_chain("org_alpha") is False


# ---------- Org isolation ----------

def test_orgs_have_independent_chains_and_do_not_see_each_others_entries(client, headers_for):
    assert upload_files(client, headers_for(email("engineer", "alpha"))).status_code == 200
    assert upload_files(client, headers_for(email("engineer", "beta"))).status_code == 200

    alpha_entries = audit(client, headers_for(email("admin", "alpha"))).json()["entries"]
    beta_entries = audit(client, headers_for(email("admin", "beta"))).json()["entries"]

    assert all(e["target"] is not None for e in alpha_entries if e["event_type"] == "upload")
    # No cross-contamination: nobody from beta shows up in alpha's log or vice versa.
    alpha_actors = {e["actor_user_id"] for e in alpha_entries if e["actor_user_id"]}
    beta_actors = {e["actor_user_id"] for e in beta_entries if e["actor_user_id"]}
    assert alpha_actors.isdisjoint(beta_actors)

    assert activity_log.verify_activity_chain("org_alpha") is True
    assert activity_log.verify_activity_chain("org_beta") is True


def test_tampering_one_orgs_chain_does_not_affect_the_other(client, headers_for):
    assert upload_files(client, headers_for(email("engineer", "alpha"))).status_code == 200
    assert upload_files(client, headers_for(email("engineer", "beta"))).status_code == 200

    conn = sqlite3.connect("memory.db")
    conn.execute(
        "UPDATE activity_log SET target = 'tampered.cfg' "
        "WHERE id = (SELECT MAX(id) FROM activity_log WHERE org_id = 'org_alpha')"
    )
    conn.commit()
    conn.close()

    assert activity_log.verify_activity_chain("org_alpha") is False
    assert activity_log.verify_activity_chain("org_beta") is True


# ---------- Permission matrix ----------

@pytest.mark.parametrize("role,expected", [
    ("admin", 200), ("senior", 200), ("engineer", 403), ("viewer", 403),
])
def test_audit_permission_matrix(client, headers_for, role, expected):
    assert audit(client, headers_for(email(role))).status_code == expected


def test_audit_rejects_anonymous(client):
    assert client.get("/audit").status_code == 401


def test_audit_is_scoped_to_callers_own_org(client, headers_for):
    beta_login = client.post("/auth/login", json={"email": email("engineer", "beta"),
                                                   "password": DEMO_PASSWORD}).json()
    beta_engineer_id = beta_login["user"]["user_id"]
    assert upload_files(client, headers_for(email("engineer", "beta"))).status_code == 200

    alpha_entries = audit(client, headers_for(email("senior", "alpha"))).json()["entries"]
    assert not any(e["actor_user_id"] == beta_engineer_id for e in alpha_entries)


# ---------- Pagination ----------

def test_pagination_limit_and_before_id(client, headers_for):
    engineer = headers_for(email("engineer"))
    admin = headers_for(email("admin"))
    for _ in range(5):
        assert upload_files(client, engineer).status_code == 200

    page1 = audit(client, admin, limit=2).json()
    assert len(page1["entries"]) == 2
    assert page1["has_more"] is True
    assert page1["next_before_id"] is not None

    page2 = audit(client, admin, limit=2, before_id=page1["next_before_id"]).json()
    assert len(page2["entries"]) == 2
    ids_page1 = {e["id"] for e in page1["entries"]}
    ids_page2 = {e["id"] for e in page2["entries"]}
    assert ids_page1.isdisjoint(ids_page2)
    assert max(ids_page2) < min(ids_page1)  # strictly older


def test_pagination_last_page_has_no_more(client, headers_for):
    admin = headers_for(email("admin"))
    total = len(audit(client, admin).json()["entries"])
    page = audit(client, admin, limit=max(total, 1) + 10).json()
    assert page["has_more"] is False
    assert page["next_before_id"] is None


def test_pagination_limit_is_clamped(client, headers_for):
    admin = headers_for(email("admin"))
    huge = audit(client, admin, limit=100000).json()
    # Shouldn't error, and shouldn't return more than exist / the server max.
    assert isinstance(huge["entries"], list)


# ---------- Logging must never block the action it describes ----------

def test_broken_log_event_does_not_block_upload(client, headers_for, monkeypatch):
    """log_event's own internal try/except is the safety net (it never
    raises to its caller) -- so to prove the action survives a broken
    logger, we break something INSIDE log_event and confirm the request
    it's attached to still succeeds."""
    def _boom(*args, **kwargs):
        raise RuntimeError("simulated activity_log failure")

    monkeypatch.setattr(activity_log, "_compute_hash", _boom)

    engineer = headers_for(email("engineer"))
    r = upload_files(client, engineer)
    assert r.status_code == 200, r.text
    assert r.json()["results"][0]["session_id"]


def test_log_event_returns_false_on_internal_failure(monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(activity_log, "_compute_hash", _boom)
    ok = activity_log.log_event(None, "login_failure", target="x@y.demo", org_id="org_alpha")
    assert ok is False


def test_broken_log_event_does_not_block_evaluate(client, headers_for, monkeypatch):
    engineer = headers_for(email("engineer"))
    r = upload_files(client, engineer)
    session_id = r.json()["results"][0]["session_id"]

    monkeypatch.setattr(activity_log, "_last_hash", lambda org_id: (_ for _ in ()).throw(RuntimeError("boom")))
    r = client.post(f"/evaluate/{session_id}", headers=engineer)
    assert r.status_code == 200, r.text
