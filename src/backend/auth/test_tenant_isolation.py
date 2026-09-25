"""
Phase 2 checkpoint: two organisations, alpha and beta, using the app at
the same time. Nothing one org uploads, teaches or votes on is visible to
or usable by the other.

Run from src/backend:  pytest auth/ -q
"""

import importlib
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from auth.conftest import DEMO_PASSWORD, SECRET

SAMPLE = (Path(__file__).resolve().parent.parent / "shared" / "sample_configs"
          / "cisco_mixed_unrecognized.txt").read_text()
TAUGHT_LINE = "logging enable"


def upload(client, headers, text=SAMPLE, **params):
    r = client.post("/upload", headers=headers, params=params,
                    files=[("files", ("router.cfg", text.encode(), "text/plain"))])
    assert r.status_code == 200, r.text
    return r.json()["results"][0]


def pending_lines(result):
    return {p["raw_line"] for p in result["pending_confirmations"]}


def vote(client, headers, session_id, line=TAUGHT_LINE, field="logging_enabled", value=True):
    return client.post("/confirm", headers=headers, json={
        "session_id": session_id,
        "confirmations": [{"raw_line": line, "field": field, "value": value}],
    })


@pytest.fixture
def alpha_session(client, headers_for):
    return upload(client, headers_for("engineer@alpha.demo"))["session_id"]


# ---------- Sessions ----------

def call(client, method, path, headers, body):
    return client.request(method.upper(), path, headers=headers, json=body)


def _session_requests(sid):
    """Every endpoint that takes a session_id. If you add one to api.py,
    add it here -- the tests below then prove it's isolated."""
    return [
        ("post", f"/evaluate/{sid}", None),
        ("get", f"/report/{sid}/pdf", None),
        ("post", "/confirm", {"session_id": sid, "confirmations": [
            {"raw_line": TAUGHT_LINE, "field": "logging_enabled", "value": True}]}),
    ]


def test_every_session_endpoint_is_covered(api_mod):
    """Fails if a new route with {session_id} is added without being listed
    in _session_requests (and therefore without an isolation test)."""
    listed = {path.replace("SID", "{session_id}") for _, path, _ in _session_requests("SID")}
    for route in api_mod.app.routes:
        if "{session_id}" in getattr(route, "path", ""):
            assert route.path in listed, f"{route.path} has no cross-org test"


@pytest.mark.parametrize("index", range(3))
def test_other_org_gets_404(client, headers_for, alpha_session, index):
    method, path, body = _session_requests(alpha_session)[index]
    r = call(client, method, path, headers_for("admin@beta.demo"), body)
    assert r.status_code == 404


@pytest.mark.parametrize("index", range(3))
def test_other_org_response_is_identical_to_nonexistent(client, headers_for, alpha_session, index):
    beta = headers_for("admin@beta.demo")
    method, path, body = _session_requests(alpha_session)[index]
    real = call(client, method, path, beta, body)

    fake_id = "00000000-0000-4000-8000-000000000000"
    method, path, body = _session_requests(fake_id)[index]
    fake = call(client, method, path, beta, body)

    assert (real.status_code, real.json()) == (fake.status_code, fake.json())


def test_same_org_teammate_can_use_session(client, headers_for, alpha_session):
    r = client.post(f"/evaluate/{alpha_session}", headers=headers_for("senior@alpha.demo"))
    assert r.status_code == 200
    assert "findings" in r.json()


def test_pdf_blocked_for_other_org_after_evaluation(client, headers_for, alpha_session):
    alpha = headers_for("engineer@alpha.demo")
    assert client.post(f"/evaluate/{alpha_session}", headers=alpha).status_code == 200
    r = client.get(f"/report/{alpha_session}/pdf", headers=headers_for("viewer@beta.demo"))
    assert r.status_code == 404


def test_blocked_attempt_does_not_modify_session(client, headers_for, api_mod, alpha_session):
    before = dict(api_mod.SESSIONS[alpha_session]["config"])
    # Two beta reviewers = enough points to promote, if the check let them in.
    vote(client, headers_for("admin@beta.demo"), alpha_session, field="ssh_enabled", value=False)
    vote(client, headers_for("senior@beta.demo"), alpha_session, field="ssh_enabled", value=False)
    assert api_mod.SESSIONS[alpha_session]["config"] == before


def test_client_cannot_choose_org_on_upload(client, headers_for, api_mod):
    sid = upload(client, headers_for("engineer@alpha.demo"), org_id="org_beta")["session_id"]
    assert api_mod.SESSIONS[sid]["org_id"] == "org_alpha"


def test_new_signup_org_is_isolated_from_demo_orgs(client, headers_for, alpha_session):
    client.post("/auth/signup", json={"email": "new@gamma.test", "password": "gamma-pass-123",
                                      "name": "New", "org_name": "Gamma"})
    gamma = headers_for("new@gamma.test", "gamma-pass-123")
    assert client.post(f"/evaluate/{alpha_session}", headers=gamma).status_code == 404


# ---------- Learned-line memory ----------

def _teach_alpha(client, headers_for, sid):
    vote(client, headers_for("admin@alpha.demo"), sid)
    second = vote(client, headers_for("senior@alpha.demo"), sid)
    assert second.json()["review_results"][0]["status"] == "promoted"


def test_learned_line_is_reused_within_org(client, headers_for, alpha_session):
    assert TAUGHT_LINE in pending_lines(upload(client, headers_for("engineer@alpha.demo")))
    _teach_alpha(client, headers_for, alpha_session)
    again = upload(client, headers_for("engineer@alpha.demo"))
    assert TAUGHT_LINE not in pending_lines(again)


def test_learned_line_is_not_shared_with_other_org(client, headers_for, alpha_session):
    _teach_alpha(client, headers_for, alpha_session)
    beta_result = upload(client, headers_for("engineer@beta.demo"))
    assert TAUGHT_LINE in pending_lines(beta_result)
    assert all(p["reasoning"] is None or "memory" not in p["reasoning"].lower()
               for p in beta_result["pending_confirmations"])


def test_votes_from_different_orgs_never_combine(client, headers_for):
    alpha_sid = upload(client, headers_for("engineer@alpha.demo"))["session_id"]
    beta_sid = upload(client, headers_for("engineer@beta.demo"))["session_id"]
    # 3 + 3 = 6 points from 2 reviewers would promote if they were one pool.
    a = vote(client, headers_for("admin@alpha.demo"), alpha_sid).json()["review_results"][0]
    b = vote(client, headers_for("senior@beta.demo"), beta_sid).json()["review_results"][0]
    assert a["status"] == b["status"] == "recorded"
    assert a["total_points"] == b["total_points"] == 3


def test_same_line_can_be_voted_in_each_org(client, headers_for):
    """UNIQUE(org_id, normalized_line, submitted_by) -- not a global unique."""
    alpha_sid = upload(client, headers_for("engineer@alpha.demo"))["session_id"]
    beta_sid = upload(client, headers_for("engineer@beta.demo"))["session_id"]
    assert vote(client, headers_for("engineer@alpha.demo"), alpha_sid).json()["review_results"][0]["status"] == "recorded"
    assert vote(client, headers_for("engineer@beta.demo"), beta_sid).json()["review_results"][0]["status"] == "recorded"


# ---------- Review report + audit chain ----------

def test_review_report_only_shows_own_org(client, headers_for, alpha_session):
    _teach_alpha(client, headers_for, alpha_session)
    beta_sid = upload(client, headers_for("engineer@beta.demo"))["session_id"]
    vote(client, headers_for("engineer@beta.demo"), beta_sid, line="archive", field="unclear", value=None)

    alpha_report = client.get("/review/report", headers=headers_for("viewer@alpha.demo")).json()
    beta_report = client.get("/review/report", headers=headers_for("viewer@beta.demo")).json()

    assert [p["normalized_line"] for p in alpha_report["promoted"]] == [TAUGHT_LINE]
    assert alpha_report["pending"] == []
    assert beta_report["promoted"] == []
    assert [p["normalized_line"] for p in beta_report["pending"]] == ["archive"]
    assert alpha_report["audit_chain_valid"] and beta_report["audit_chain_valid"]


def test_tampering_breaks_only_that_orgs_chain(client, headers_for, alpha_session):
    _teach_alpha(client, headers_for, alpha_session)
    beta_sid = upload(client, headers_for("engineer@beta.demo"))["session_id"]
    vote(client, headers_for("admin@beta.demo"), beta_sid)
    vote(client, headers_for("senior@beta.demo"), beta_sid)

    conn = sqlite3.connect("memory.db")
    conn.execute("UPDATE audit_log SET value_str = 'false' WHERE org_id = 'org_alpha'")
    conn.commit()

    alpha = client.get("/review/report", headers=headers_for("viewer@alpha.demo")).json()
    beta = client.get("/review/report", headers=headers_for("viewer@beta.demo")).json()
    assert alpha["audit_chain_valid"] is False
    assert beta["audit_chain_valid"] is True


def test_moving_an_entry_to_another_org_is_detected(client, headers_for, alpha_session):
    _teach_alpha(client, headers_for, alpha_session)
    beta_sid = upload(client, headers_for("engineer@beta.demo"))["session_id"]
    vote(client, headers_for("admin@beta.demo"), beta_sid, line="archive", field="unclear", value=None)
    vote(client, headers_for("senior@beta.demo"), beta_sid, line="archive", field="unclear", value=None)

    conn = sqlite3.connect("memory.db")
    conn.execute("UPDATE audit_log SET org_id = 'org_beta' WHERE org_id = 'org_alpha'")
    conn.commit()
    beta = client.get("/review/report", headers=headers_for("viewer@beta.demo")).json()
    assert beta["audit_chain_valid"] is False


def test_review_system_rejects_cross_org_vote(api_mod):
    """Defence in depth below the API: review_system itself refuses."""
    from block2b import review_system
    from auth import store
    user, _ = store.get_credentials("admin@alpha.demo")
    with pytest.raises(PermissionError):
        review_system.submit_review("x", "unclear", None, submitted_by=user.user_id, org_id="org_beta")


# ---------- Migration from pre-Phase-2 tables ----------

def _chain(rows):
    """Build a valid legacy (global) chain the way the old code did."""
    from block2b.review_system import _compute_hash
    prev, out = "GENESIS", []
    for line, ts in rows:
        payload = {"normalized_line": line, "field": "logging_enabled", "value_str": "true",
                   "total_points": 6, "num_reviewers": 2, "timestamp": ts}
        h = _compute_hash(prev, payload)
        out.append((line, "logging_enabled", "true", 6, 2, ts, prev, h))
        prev = h
    return out


def test_legacy_tables_migrate_into_alpha(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.setenv("DEMO_PASSWORD", DEMO_PASSWORD)
    monkeypatch.setenv("GROQ_API_KEY", "")

    conn = sqlite3.connect("memory.db")
    conn.executescript("""
        CREATE TABLE confirmed_lines (normalized_line TEXT PRIMARY KEY, raw_line TEXT NOT NULL,
            field TEXT NOT NULL, value TEXT, value_type TEXT NOT NULL, vendor_hint TEXT,
            confirmed_by TEXT, source TEXT DEFAULT 'human_confirmed');
        INSERT INTO confirmed_lines VALUES ('logging enable', 'logging enable', 'logging_enabled',
            'true', 'bool', 'cisco', 'consensus:2_reviewers', 'human_confirmed');
        CREATE TABLE review_staging (id INTEGER PRIMARY KEY AUTOINCREMENT, normalized_line TEXT NOT NULL,
            raw_line TEXT NOT NULL, field TEXT NOT NULL, value_str TEXT, value_type TEXT NOT NULL,
            vendor_hint TEXT, submitted_by TEXT NOT NULL, role TEXT NOT NULL, points INTEGER NOT NULL,
            timestamp REAL NOT NULL, UNIQUE(normalized_line, submitted_by));
        INSERT INTO review_staging (normalized_line, raw_line, field, value_type, submitted_by, role, points, timestamp)
            VALUES ('archive', 'archive', 'unclear', 'none', 'alice', 'senior_engineer', 3, 1);
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, normalized_line TEXT NOT NULL,
            field TEXT NOT NULL, value_str TEXT, total_points INTEGER NOT NULL, num_reviewers INTEGER NOT NULL,
            timestamp REAL NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
    """)
    conn.executemany(
        "INSERT INTO audit_log (normalized_line, field, value_str, total_points, num_reviewers, "
        "timestamp, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        _chain([("logging enable", 1.0), ("ip ssh time-out 60", 2.0)]),
    )
    conn.commit()
    conn.close()

    import api
    api = importlib.reload(api)
    client = TestClient(api.app)

    def h(email):
        token = client.post("/auth/login", json={"email": email, "password": DEMO_PASSWORD}).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    # Learned line kept, now alpha's only.
    assert TAUGHT_LINE not in pending_lines(upload(client, h("engineer@alpha.demo")))
    assert TAUGHT_LINE in pending_lines(upload(client, h("engineer@beta.demo")))

    # Old chain kept intact under alpha; ghost vote from "alice" dropped.
    report = client.get("/review/report", headers=h("viewer@alpha.demo")).json()
    assert len(report["promoted"]) == 2 and report["audit_chain_valid"] is True
    assert report["pending"] == []
    assert client.get("/review/report", headers=h("viewer@beta.demo")).json()["promoted"] == []

    # Running startup again is a no-op.
    importlib.reload(api)
    assert client.get("/review/report", headers=h("viewer@alpha.demo")).json()["audit_chain_valid"] is True
