"""
Tests for whatif.simulator. Runs against the real shared.schema /
compliance_engine.evaluate contract (Phase 5.6+ reconciliation) -- no
local stub. NormalizedConfig's 6 fields matched the original
assumption exactly (see SIH_26155_handoff_v2.md), so only RULE_PACK's
shape needed updating here: evaluate_config expects a dict with a
"rules" key of rule dicts (id/field/expected/severity/explanation/
remediation), matching rule_packs/*.yaml -- not the flat tuple list
this test originally stubbed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from shared.schema import NormalizedConfig  # noqa: E402
from whatif.simulator import simulate_change, _with_overrides, SimulationError  # noqa: E402

# Real rule_pack shape: dict with "rules" key, each rule a dict of
# id/field/expected/severity/explanation/remediation (vendor -> CLI).
RULE_PACK = {
    "framework": "CIS",
    "rules": [
        {
            "id": "CIS-4.2.1", "field": "telnet_enabled", "expected": False,
            "severity": "high", "explanation": "Telnet transmits credentials in cleartext.",
            "remediation": {"cisco_iosxe_cli": "no telnet-server"},
        },
        {
            "id": "CIS-4.2.2", "field": "ssh_enabled", "expected": True,
            "severity": "high", "explanation": "SSH encrypts remote administration sessions.",
            "remediation": {"cisco_iosxe_cli": "ip ssh version 2"},
        },
        {
            "id": "CIS-4.3.1", "field": "password_encryption", "expected": "not in: cleartext, none",
            "severity": "critical", "explanation": "Passwords must not be stored in cleartext.",
            "remediation": {"cisco_iosxe_cli": "service password-encryption"},
        },
        {
            "id": "NIST-AC-2", "field": "banner_configured", "expected": True,
            "severity": "medium", "explanation": "A login banner should be configured.",
            "remediation": {"cisco_iosxe_cli": "banner motd ^Cauthorized use only^C"},
        },
    ],
}


def _config(**kwargs) -> NormalizedConfig:
    defaults = dict(
        ssh_enabled=True, telnet_enabled=True, session_timeout_seconds=600,
        logging_enabled=True, password_encryption="cleartext", banner_configured=None,
    )
    defaults.update(kwargs)
    return NormalizedConfig(**defaults)


def test_simulate_change_flips_a_finding_and_lowers_risk():
    base = _config(telnet_enabled=True, password_encryption="cleartext")
    result = simulate_change(
        base, overrides={"telnet_enabled": False, "password_encryption": "md5"},
        vendor="cisco_iosxe_cli", rule_pack=RULE_PACK,
    )
    flipped_ids = {d["rule_id"] for d in result["findings_diff"]}
    assert "CIS-4.2.1" in flipped_ids  # telnet FAIL -> PASS
    assert "CIS-4.3.1" in flipped_ids  # password_encryption FAIL -> PASS
    diff_by_id = {d["rule_id"]: d for d in result["findings_diff"]}
    assert diff_by_id["CIS-4.2.1"] == {
        "rule_id": "CIS-4.2.1", "before_status": "FAIL", "after_status": "PASS",
    }
    assert result["after_score"] < result["before_score"]


def test_simulate_change_never_mutates_original_config():
    base = _config(telnet_enabled=True)
    original_snapshot = base.model_copy()
    simulate_change(
        base, overrides={"telnet_enabled": False},
        vendor="cisco_iosxe_cli", rule_pack=RULE_PACK,
    )
    assert base == original_snapshot
    assert base.telnet_enabled is True  # untouched


def test_simulate_change_no_op_overrides_no_diff():
    base = _config()
    result = simulate_change(
        base, overrides={}, vendor="cisco_iosxe_cli", rule_pack=RULE_PACK,
    )
    assert result["findings_diff"] == []
    assert result["before_score"] == result["after_score"]


def test_simulate_change_rejects_unknown_field():
    base = _config()
    with pytest.raises(SimulationError):
        simulate_change(
            base, overrides={"not_a_real_field": True},
            vendor="cisco_iosxe_cli", rule_pack=RULE_PACK,
        )


def test_simulate_change_can_make_things_worse_too():
    # Doc only says "flip status" -- doesn't require the change to be
    # an improvement. A regression should surface just as clearly.
    base = _config(ssh_enabled=True)
    result = simulate_change(
        base, overrides={"ssh_enabled": False},
        vendor="cisco_iosxe_cli", rule_pack=RULE_PACK,
    )
    diff_by_id = {d["rule_id"]: d for d in result["findings_diff"]}
    assert diff_by_id["CIS-4.2.2"] == {
        "rule_id": "CIS-4.2.2", "before_status": "PASS", "after_status": "FAIL",
    }
    assert result["after_score"] > result["before_score"]


def test_with_overrides_supports_dataclass_configs_too():
    from dataclasses import dataclass

    @dataclass
    class DummyConfig:
        ssh_enabled: bool
        telnet_enabled: bool

    original = DummyConfig(ssh_enabled=True, telnet_enabled=True)
    updated = _with_overrides(original, {"telnet_enabled": False})
    assert updated.telnet_enabled is False
    assert original.telnet_enabled is True  # original untouched
    assert updated is not original


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
