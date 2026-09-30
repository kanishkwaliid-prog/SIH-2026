"""Guards the Phase 0 decisions so a later edit can't quietly break them.
Run from src/backend:  pytest auth/test_config.py"""

import pytest

from auth import config
from auth.config import Permission, Role


def test_every_role_has_permissions():
    assert set(config.ROLE_PERMISSIONS) == set(Role)


def test_admin_has_everything_viewer_is_read_only():
    assert config.ROLE_PERMISSIONS[Role.ADMIN] == frozenset(Permission)
    assert config.ROLE_PERMISSIONS[Role.VIEWER] == {Permission.VIEW_REPORTS}


def test_only_admin_manages_users():
    for role in Role:
        assert config.has_permission(role.value, Permission.MANAGE_USERS) == (role is Role.ADMIN)


def test_vote_weights_match_confirm_permission():
    # Anyone who may call /confirm must have a vote weight, and vice versa.
    voters = {r for r in Role if config.has_permission(r.value, Permission.CONFIRM)}
    assert voters == set(config.ROLE_VOTE_WEIGHTS)


def test_no_single_reviewer_can_promote():
    # Mirrors review_system.THRESHOLD = 6 with MIN_REVIEWERS = 2.
    assert max(config.ROLE_VOTE_WEIGHTS.values()) < 6


def test_unknown_role_fails_closed():
    assert config.has_permission("superuser", Permission.VIEW_REPORTS) is False
    assert config.has_permission("", Permission.UPLOAD) is False


def test_role_defaults():
    assert config.SIGNUP_CREATES_ORG_AS is Role.ADMIN
    assert config.DEFAULT_MEMBER_ROLE is Role.VIEWER


def test_jwt_secret_required(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "too-short")
    with pytest.raises(RuntimeError):
        config.get_jwt_secret()
    monkeypatch.setenv("JWT_SECRET", "x" * 48)
    assert config.get_jwt_secret() == "x" * 48
