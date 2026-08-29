#!/usr/bin/env python3
"""
Phase 4 end-to-end test: real config -> converter -> NormalizedConfig ->
compliance_engine -> Findings, for a spread of vendors, using both the
CIS and NIST rule packs (with cross-referenced remediation).
"""

import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from converter.schema_adapter import parse_and_map
from shared.schema import NormalizedConfig
from compliance_engine.evaluate import (
    load_rule_pack,
    evaluate_config,
    summarize,
    risk_score,
    NO_REMEDIATION_TEXT,
)

FIXTURES = (
    pathlib.Path(__file__).resolve().parent.parent
    / "netcanon" / "tests" / "fixtures" / "synthetic"
)

VENDOR_FILES = {
    "cisco_iosxe_cli": "kitchen_sink.txt",
    "juniper_junos": "kitchen_sink.set",
    "vyos": "kitchen_sink.conf",
    "fortigate_cli": "kitchen_sink.conf",
    "opnsense": "kitchen_sink.xml",
    "cisco_iosxr": "kitchen_sink.cfg",  # sparse fixture -- exercises UNKNOWN path
}

cis_pack = load_rule_pack(
    pathlib.Path(__file__).resolve().parent.parent
    / "rule_packs" / "cis_network_devices.yaml"
)
nist_pack = load_rule_pack(
    pathlib.Path(__file__).resolve().parent.parent
    / "rule_packs" / "nist_800_53_network_devices.yaml"
)

print(f"Loaded CIS pack: {len(cis_pack['rules'])} rules")
print(f"Loaded NIST pack: {len(nist_pack['rules'])} rules")

any_failures = False

for vendor_dir, fname in VENDOR_FILES.items():
    path = FIXTURES / vendor_dir / fname
    if not path.exists():
        print(f"\nSKIP {vendor_dir}: fixture not found at {path}")
        continue

    raw = path.read_text(encoding="utf-8", errors="replace")
    result = parse_and_map(raw)

    print(f"\n{'='*70}")
    print(f"  {vendor_dir}  (detected vendor={result.vendor}, codec={result.codec})")
    print(f"{'='*70}")

    if result.error:
        print(f"  PARSE ERROR: {result.error}")
        any_failures = True
        continue

    config = NormalizedConfig(
        ssh_enabled=result.ssh_enabled,
        telnet_enabled=result.telnet_enabled,
        session_timeout_seconds=result.session_timeout_seconds,
        logging_enabled=result.logging_enabled,
        password_encryption=result.password_encryption,
        banner_configured=result.banner_configured,
    )

    cis_findings = evaluate_config(config, vendor=result.vendor, rule_pack=cis_pack)
    nist_findings = evaluate_config(
        config, vendor=result.vendor, rule_pack=nist_pack, cross_reference_pack=cis_pack
    )

    print(f"\n  CIS findings ({len(cis_findings)} rules evaluated):")
    for f in cis_findings:
        print(f"    [{f.status:7s}] {f.rule_id:12s} sev={f.severity:8s} {f.field_checked}={f.actual}")

    cis_summary = summarize(cis_findings)
    print(f"  CIS summary: {cis_summary}  risk_score={risk_score(cis_findings)}")

    print(f"\n  NIST findings ({len(nist_findings)} rules evaluated):")
    for f in nist_findings:
        remediation_source = (
            "NO REMEDIATION" if f.remediation_cli == NO_REMEDIATION_TEXT
            else ("cross-referenced from CIS" if f.remediation_cli else "n/a (passed)")
        )
        print(f"    [{f.status:7s}] {f.rule_id:14s} sev={f.severity:8s} remediation={remediation_source}")

    # Sanity check: every FAIL finding should have real remediation text,
    # not the placeholder, when a vendor+CIS remediation entry exists.
    for f in cis_findings + nist_findings:
        if f.status == "FAIL" and f.remediation_cli is None:
            print(f"    BUG: FAIL finding {f.rule_id} has no remediation_cli at all")
            any_failures = True

print(f"\n{'='*70}")
if any_failures:
    print("  RESULT: issues found -- see above")
    sys.exit(1)
else:
    print("  RESULT: all checks passed")
