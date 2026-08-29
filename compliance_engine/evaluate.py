"""
Block 3 — Compliance evaluation engine.

Reads a NormalizedConfig (produced by Block 2 / converter) plus a rule
pack (YAML), evaluates every rule, and returns a list[Finding] exactly
matching the shared/schema.py contract that Block 4 consumes.

Usage:
    from compliance_engine.evaluate import load_rule_pack, evaluate_config
    pack = load_rule_pack("rule_packs/cis_network_devices.yaml")
    findings = evaluate_config(normalized_config, vendor="cisco_iosxe_cli", rule_pack=pack)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared.schema import Finding, NormalizedConfig

# Placeholder text shown when a rule has no remediation entry for the
# detected vendor. Never invent CLI syntax here -- an empty/flagged
# remediation is far safer than a plausible-looking wrong command.
NO_REMEDIATION_TEXT = (
    "No verified remediation command available for this vendor yet. "
    "Consult vendor documentation before making changes."
)

_NUMERIC_RE = re.compile(r"^\s*(<=|>=|<|>|==|!=)\s*(-?\d+(?:\.\d+)?)\s*$")


class RulePackError(ValueError):
    """Raised when a rule pack file is malformed."""


def load_rule_pack(path: str | Path) -> dict[str, Any]:
    """Load and lightly validate a YAML rule pack."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        pack = yaml.safe_load(f)

    if not isinstance(pack, dict) or "rules" not in pack:
        raise RulePackError(f"{path}: rule pack must be a dict with a 'rules' key")

    for rule in pack["rules"]:
        for required in ("id", "field", "expected", "severity", "explanation"):
            if required not in rule:
                raise RulePackError(f"{path}: rule missing required key '{required}': {rule}")
        if rule["severity"] not in ("low", "medium", "high", "critical"):
            raise RulePackError(
                f"{path}: rule {rule['id']} has invalid severity '{rule['severity']}'"
            )

    return pack


def _condition_matches(actual: Any, expected: Any) -> bool:
    """Evaluate one rule's expected condition against the actual value.

    Supported `expected` forms:
      - bool                      -> exact equality
      - "not none"                -> actual is not None (and not the string "none")
      - "<= N" / "< N" / ">= N" / "> N" / "== N" / "!= N"  -> numeric comparison
      - "not in: a, b, c"         -> actual (case-insensitive) is not one of a/b/c
      - anything else (string)    -> exact equality (case-insensitive for strings)
    """
    if actual is None:
        # A None actual means the converter couldn't determine this field
        # from the config at all -- that's a distinct outcome from FAIL,
        # handled by the caller (evaluate_config), not this function.
        raise ValueError("_condition_matches should not be called with actual=None")

    if isinstance(expected, bool):
        return bool(actual) == expected

    if isinstance(expected, (int, float)):
        return actual == expected

    if isinstance(expected, str):
        expected_norm = expected.strip()

        if expected_norm.lower() == "not none":
            return actual is not None and str(actual).strip().lower() != "none"

        num_match = _NUMERIC_RE.match(expected_norm)
        if num_match:
            op, num_str = num_match.groups()
            num = float(num_str)
            try:
                actual_num = float(actual)
            except (TypeError, ValueError):
                return False
            return {
                "<=": actual_num <= num,
                ">=": actual_num >= num,
                "<": actual_num < num,
                ">": actual_num > num,
                "==": actual_num == num,
                "!=": actual_num != num,
            }[op]

        if expected_norm.lower().startswith("not in:"):
            excluded = [
                x.strip().lower() for x in expected_norm.split(":", 1)[1].split(",")
            ]
            return str(actual).strip().lower() not in excluded

        if expected_norm.lower().startswith("in:"):
            allowed = [
                x.strip().lower() for x in expected_norm.split(":", 1)[1].split(",")
            ]
            return str(actual).strip().lower() in allowed

        # Fallback: exact (case-insensitive) string match
        return str(actual).strip().lower() == expected_norm.lower()

    raise RulePackError(f"Unsupported 'expected' type: {type(expected)} ({expected!r})")


def _get_remediation(
    rule: dict[str, Any],
    vendor: str,
    cross_reference_pack: dict[str, Any] | None = None,
) -> str:
    remediation_map = rule.get("remediation")

    if not remediation_map and cross_reference_pack is not None:
        ref_id = rule.get("see_cis_rule")
        if ref_id:
            ref_rule = next(
                (r for r in cross_reference_pack["rules"] if r["id"] == ref_id), None
            )
            if ref_rule is not None:
                remediation_map = ref_rule.get("remediation", {})

    if not remediation_map:
        return NO_REMEDIATION_TEXT

    text = remediation_map.get(vendor)
    if text is None or not text.strip():
        return NO_REMEDIATION_TEXT
    return text.strip()


def evaluate_config(
    config: NormalizedConfig,
    vendor: str,
    rule_pack: dict[str, Any],
    cross_reference_pack: dict[str, Any] | None = None,
) -> list[Finding]:
    """Evaluate every rule in *rule_pack* against *config*.

    *vendor* should be the specific codec/vendor string (e.g.
    "cisco_iosxe_cli"), matching converter.schema_adapter's
    ComplianceResult.vendor field -- NOT the generic vendor_family --
    so remediation lookups resolve to the right config surface.

    *cross_reference_pack* is optional: if a rule in *rule_pack* has no
    `remediation` block of its own but has a `see_cis_rule` key (used by
    rule_packs/nist_800_53_network_devices.yaml to avoid duplicating
    CLI commands already in the CIS pack), pass the loaded CIS pack here
    and matching remediation text will be pulled from it.

    A field that is None in the config (the converter couldn't determine
    it from the source config) produces a finding with status
    "UNKNOWN" rather than PASS or FAIL: we should never claim a device
    fails a check we don't actually have data for.
    """
    findings: list[Finding] = []
    framework = rule_pack.get("framework", "UNKNOWN")

    for rule in rule_pack["rules"]:
        field_name = rule["field"]
        actual_value = getattr(config, field_name, None)

        if actual_value is None:
            findings.append(
                Finding(
                    rule_id=rule["id"],
                    status="UNKNOWN",
                    severity=rule["severity"],
                    field_checked=field_name,
                    expected=str(rule["expected"]),
                    actual="not present in config",
                    explanation=(
                        f"{rule['explanation']} (This device's config did not "
                        f"contain enough information to check this rule.)"
                    ),
                    remediation_cli=None,
                )
            )
            continue

        passed = _condition_matches(actual_value, rule["expected"])
        status = "PASS" if passed else "FAIL"

        findings.append(
            Finding(
                rule_id=rule["id"],
                status=status,
                severity=rule["severity"],
                field_checked=field_name,
                expected=str(rule["expected"]),
                actual=str(actual_value),
                explanation=rule["explanation"],
                remediation_cli=(
                    _get_remediation(rule, vendor, cross_reference_pack)
                    if not passed
                    else None
                ),
            )
        )

    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    """Quick counts by status, useful for the report generator / UI."""
    summary = {"PASS": 0, "FAIL": 0, "UNKNOWN": 0}
    for f in findings:
        summary[f.status] = summary.get(f.status, 0) + 1
    return summary


def risk_score(findings: list[Finding]) -> int:
    """Simple weighted risk score: critical=3, high=2, medium=1, low=0.5.

    Used by the what-if simulator (Phase 6) and snapshot/revert (Phase 7)
    to compare risk before vs. after a change. Only FAIL findings count
    -- PASS and UNKNOWN don't contribute.
    """
    weights = {"critical": 3, "high": 2, "medium": 1, "low": 0.5}
    return round(
        sum(weights.get(f.severity, 0) for f in findings if f.status == "FAIL"), 2
    )
