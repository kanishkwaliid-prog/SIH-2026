"""
Phase 6 checkpoint: GET /sessions lets a viewer discover which session
ids exist to open (previously they could only use one if handed the id
directly), without leaking another org's sessions or any session's
raw_text/device/config.

Run from src/backend:  pytest auth/ -q
"""

from pathlib import Path

import activity_log
import pytest

from auth.conftest import DEMO_PASSWORD

SAMPLE = (Path(__file__).resolve().parent.parent / "shared" / "sample_configs"
          / "cisco_mixed_unrecognized.txt").read_text()

ROLES = ["admin", "senior", "engineer", "viewer"]


def email(role, org="alpha"):
    return f"{role}@{org}.demo"


def upload_files(client, headers, text=SAMPLE, filename="router.cfg"):
    return client.post("/upload", headers=headers,
                       files=[("files", (filename, text.encode(), "text/plain"))])


@pytest.fixture
def alpha_session(client, headers_for):
    r = upload_files(client, headers_for(email("engineer")))
    assert r.status_code == 200, r.text
    return r.json()["results"][0]


# ---------- Permission matrix ----------
# VIEW_REPORTS is granted to all four demo roles (auth/config.py), so
# /sessions -- gated on that same permission -- is a 200 for everyone
# signed in and a 401 for nobody.

@pytest.mark.parametrize("role", ROLES)
def test_sessions_permission_matrix(client, headers_for, alpha_session, role):
    r = client.get("/sessions", headers=headers_for(email(role)))
    assert r.status_code == 200, r.text


def test_anonymous_rejected(client, alpha_session):
    assert client.get("/sessions").status_code == 401


# ---------- Shape of the response ----------

def test_lists_the_uploaded_session(client, headers_for, alpha_session):
    r = client.get("/sessions", headers=headers_for(email("viewer")))
    sessions = r.json()["sessions"]
    assert len(sessions) == 1
    entry = sessions[0]
    assert entry["session_id"] == alpha_session["session_id"]
    assert entry["filename"] == "router.cfg"
    assert entry["evaluated"] is False


def test_never_exposes_session_content(client, headers_for, alpha_session):
    r = client.get("/sessions", headers=headers_for(email("viewer")))
    entry = r.json()["sessions"][0]
    assert set(entry) == {"session_id", "filename", "evaluated"}


def test_evaluated_flag_flips_after_evaluate(client, headers_for, alpha_session):
    sid = alpha_session["session_id"]
    before = client.get("/sessions", headers=headers_for(email("viewer"))).json()["sessions"][0]
    assert before["evaluated"] is False

    r = client.post(f"/evaluate/{sid}", headers=headers_for(email("engineer")))
    assert r.status_code == 200, r.text

    after = client.get("/sessions", headers=headers_for(email("viewer"))).json()["sessions"][0]
    assert after["evaluated"] is True


def test_viewer_can_now_reach_a_session_it_discovered(client, headers_for, alpha_session):
    """The actual point of the endpoint: a viewer that could only read
    /review/report and download a PDF for a session_id it was handed can
    now find that id itself, then use it exactly as before."""
    sid = client.get("/sessions", headers=headers_for(email("viewer"))).json()["sessions"][0]["session_id"]
    r = client.get(f"/report/{sid}/pdf", headers=headers_for(email("viewer")))
    assert r.status_code == 400  # permission granted -- "not evaluated yet", not a 403/404


def test_lists_multiple_sessions_newest_included(client, headers_for, alpha_session):
    upload_files(client, headers_for(email("engineer")), filename="switch.cfg")
    sessions = client.get("/sessions", headers=headers_for(email("viewer"))).json()["sessions"]
    assert {s["filename"] for s in sessions} == {"router.cfg", "switch.cfg"}


# ---------- Org isolation ----------
# Scoped the same way _get_session_for() scopes single-session access in
# api.py, so this gets its own coverage rather than being folded into
# auth/test_tenant_isolation.py's {session_id}-route sweep (this route
# takes no session_id -- there's nothing for _session_requests() to list).

def test_other_org_sees_nothing(client, headers_for, alpha_session):
    r = client.get("/sessions", headers=headers_for(email("viewer", "beta")))
    assert r.json()["sessions"] == []


def test_each_org_sees_only_its_own(client, headers_for, alpha_session):
    upload_files(client, headers_for(email("engineer", "beta")), filename="beta.cfg")

    alpha = client.get("/sessions", headers=headers_for(email("viewer"))).json()["sessions"]
    beta = client.get("/sessions", headers=headers_for(email("viewer", "beta"))).json()["sessions"]

    assert [s["filename"] for s in alpha] == ["router.cfg"]
    assert [s["filename"] for s in beta] == ["beta.cfg"]
    assert alpha[0]["session_id"] != beta[0]["session_id"]


# ---------- Logging ----------
# Deliberately NOT logged -- see the endpoint's docstring. Confirms the
# design decision rather than just asserting current behaviour by accident.

def test_listing_sessions_is_not_logged(client, headers_for, alpha_session):
    viewer = headers_for(email("viewer"))  # log in first -- login_success is logged
    before = activity_log.list_activity_log("org_alpha")["entries"]
    client.get("/sessions", headers=viewer)
    after = activity_log.list_activity_log("org_alpha")["entries"]
    assert before == after
