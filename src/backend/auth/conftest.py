"""
Shared fixtures for the auth test suite. Each test gets a fresh, empty
database in a temp folder -- your real memory.db is never touched -- and
the LLM is switched off so tests are fast, free and deterministic
(unknown lines come back "unclear", the documented Tier 3 path).
"""

import importlib

import pytest
from fastapi.testclient import TestClient

SECRET = "test-secret-" + "x" * 40
DEMO_PASSWORD = "demo-password-123"


@pytest.fixture
def api_mod(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # memory.DB_PATH is relative ("memory.db")
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.setenv("DEMO_PASSWORD", DEMO_PASSWORD)
    monkeypatch.setenv("GROQ_API_KEY", "")
    from block2b import llm_classifier
    monkeypatch.setattr(llm_classifier, "_client", None)
    from auth import lockout
    lockout.clear_all()
    import api
    return importlib.reload(api)  # re-runs startup against the temp DB


@pytest.fixture
def client(api_mod):
    return TestClient(api_mod.app)


@pytest.fixture
def headers_for(client):
    """headers_for("engineer@alpha.demo") -> {"Authorization": "Bearer ..."}"""
    cache = {}

    def _headers(email, password=DEMO_PASSWORD):
        if email not in cache:
            r = client.post("/auth/login", json={"email": email, "password": password})
            assert r.status_code == 200, r.text
            cache[email] = {"Authorization": f"Bearer {r.json()['access_token']}"}
        return cache[email]

    return _headers
