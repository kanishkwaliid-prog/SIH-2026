"""
Tests for report_generator. Runs against the real shared.schema /
compliance_engine contract (Phase 5.6+ reconciliation) -- no local
stub. See SIH_26155_handoff_v2.md's "CRITICAL FIRST STEP" for what
changed vs. the original assumed field names:
  - Finding.field  -> Finding.field_checked
  - DeviceInfo.serial -> DeviceInfo.serial_number
  - Finding also requires `expected` / `actual` (str, no default)
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.schema import DeviceInfo, Finding, ComplianceReport  # noqa: E402
from report_generator.generator import build_findings_rows, generate_pdf  # noqa: E402
from report_generator.explain import ExplanationError  # noqa: E402


def _sample_report() -> ComplianceReport:
    device = DeviceInfo(vendor="cisco_iosxe_cli", hostname="edge-sw-1",
                         serial_number="ABC123", os_version="17.9")
    findings = [
        Finding(rule_id="CIS-4.2.1", status="FAIL", severity="high",
                field_checked="telnet_enabled", expected="False", actual="True",
                remediation_cli="no telnet-server",
                explanation="Telnet is enabled, which transmits credentials in cleartext."),
        Finding(rule_id="CIS-4.2.2", status="PASS", severity="high",
                field_checked="ssh_enabled", expected="True", actual="True"),
        Finding(rule_id="NIST-AC-2", status="UNKNOWN", severity="medium",
                field_checked="banner_configured", expected="True", actual="not present in config"),
        Finding(rule_id="CIS-4.3.1", status="FAIL", severity="critical",
                field_checked="password_encryption", expected="not in: cleartext, none", actual="cleartext",
                remediation_cli="service password-encryption",
                explanation="Passwords stored in cleartext or weak encoding."),
    ]
    return ComplianceReport(device=device, framework="CIS", findings=findings)


def _fake_explain(finding) -> str:
    return f"Fake plain-English explanation for {finding.rule_id}."


def _failing_explain(finding) -> str:
    raise ExplanationError("simulated AI outage")


def test_build_findings_rows_only_calls_explain_for_fail():
    report = _sample_report()
    calls = []

    def tracking_explain(finding):
        calls.append(finding.rule_id)
        return _fake_explain(finding)

    rows = build_findings_rows(report, explain_fn=tracking_explain)

    # Explanation was requested only for the two FAIL findings.
    assert calls == ["CIS-4.2.1", "CIS-4.3.1"]

    by_id = {r.rule_id: r for r in rows}
    assert by_id["CIS-4.2.1"].llm_explanation == "Fake plain-English explanation for CIS-4.2.1."
    assert by_id["CIS-4.2.2"].llm_explanation is None  # PASS never gets one
    assert by_id["NIST-AC-2"].llm_explanation is None  # UNKNOWN never gets one


def test_remediation_cli_passed_through_verbatim():
    report = _sample_report()
    rows = build_findings_rows(report, explain_fn=_fake_explain)
    by_id = {r.rule_id: r for r in rows}
    assert by_id["CIS-4.2.1"].remediation_cli == "no telnet-server"
    assert by_id["CIS-4.3.1"].remediation_cli == "service password-encryption"
    # PASS/UNKNOWN findings never carry remediation text.
    assert by_id["CIS-4.2.2"].remediation_cli is None
    assert by_id["NIST-AC-2"].remediation_cli is None


def test_unknown_is_never_treated_as_fail():
    report = _sample_report()
    rows = build_findings_rows(report, explain_fn=_fake_explain)
    unknown_row = next(r for r in rows if r.rule_id == "NIST-AC-2")
    assert unknown_row.status == "UNKNOWN"
    assert unknown_row.remediation_cli is None
    assert unknown_row.llm_explanation is None


def test_ai_failure_degrades_gracefully_not_fatal():
    report = _sample_report()
    rows = build_findings_rows(report, explain_fn=_failing_explain)
    fail_rows = [r for r in rows if r.status == "FAIL"]
    assert len(fail_rows) == 2
    for r in fail_rows:
        assert r.llm_explanation is None
        assert r.explanation_error == "simulated AI outage"
        # Remediation CLI is completely independent of whether the AI call worked.
        assert r.remediation_cli


def test_generate_pdf_writes_a_real_file():
    report = _sample_report()
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "report.pdf"
        result_path = generate_pdf(report, out, explain_fn=_fake_explain)
        assert Path(result_path).exists()
        assert Path(result_path).stat().st_size > 500  # not an empty/broken file
        with open(result_path, "rb") as f:
            assert f.read(4) == b"%PDF"


def test_generate_pdf_with_no_fail_findings():
    device = DeviceInfo(vendor="vyos", hostname="core-1")
    findings = [Finding(rule_id="CIS-1.1", status="PASS", severity="low",
                         field_checked="ssh_enabled", expected="True", actual="True")]
    report = ComplianceReport(device=device, framework="CIS", findings=findings)
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "clean.pdf"
        result_path = generate_pdf(report, out, explain_fn=_fake_explain)
        assert Path(result_path).exists()


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
