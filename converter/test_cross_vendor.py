#!/usr/bin/env python3
"""
Phase 3.5 test: Run detect_vendor + parse_and_map against ALL vendor
kitchen-sink fixtures under netcanon/tests/fixtures/synthetic/.

For each vendor, prints the detected vendor, compliance fields, and
flags any vendor where more than half the fields are None.
"""

import sys, os, pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from converter.schema_adapter import detect_vendor, parse_and_map

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "netcanon" / "tests" / "fixtures" / "synthetic"

# Map vendor folder names to their fixture file extension
VENDOR_FILES = {
    "arista_eos": "kitchen_sink.txt",
    "aruba_aoscx": "kitchen_sink.cfg",
    "aruba_aoss": "kitchen_sink.cfg",
    "cisco_iosxe": "kitchen_sink.xml",
    "cisco_iosxe_cli": "kitchen_sink.txt",
    "cisco_iosxr": "kitchen_sink.cfg",
    "cisco_nxos": "kitchen_sink.cfg",
    "fortigate_cli": "kitchen_sink.conf",
    "juniper_junos": "kitchen_sink.set",
    "mikrotik_routeros": "kitchen_sink.rsc",
    "opnsense": "kitchen_sink.xml",
    "vyos": "kitchen_sink.conf",
}

COMPLIANCE_FIELDS = [
    "ssh_enabled", "telnet_enabled", "session_timeout_seconds",
    "logging_enabled", "password_encryption", "banner_configured",
]

results_summary = []

for vendor_folder, fname in sorted(VENDOR_FILES.items()):
    path = FIXTURES / vendor_folder / fname
    if not path.exists():
        print(f"\n{'='*70}")
        print(f"  {vendor_folder} — SKIP (file not found: {path})")
        print(f"{'='*70}")
        continue

    raw = path.read_text(encoding="utf-8", errors="replace")

    print(f"\n{'='*70}")
    print(f"  {vendor_folder}  ({fname})")
    print(f"{'='*70}")

    # --- detect_vendor ---
    candidates = detect_vendor(raw)
    if candidates:
        print(f"\n  Detected vendor candidates:")
        for c in candidates[:3]:
            print(f"    {c.codec}: confidence={c.confidence}  ({c.reason})")
    else:
        print(f"\n  WARNING: no vendor detected!")

    # --- parse_and_map ---
    result = parse_and_map(raw)
    print(f"\n  Compliance fields:")
    print(f"    vendor               = {result.vendor}")
    print(f"    codec                = {result.codec}")
    print(f"    vendor_family        = {result.vendor_family}")
    print(f"    confidence           = {result.confidence}")
    print(f"    ssh_enabled          = {result.ssh_enabled}")
    print(f"    telnet_enabled       = {result.telnet_enabled}")
    print(f"    session_timeout_sec  = {result.session_timeout_seconds}")
    print(f"    logging_enabled      = {result.logging_enabled}")
    print(f"    password_encryption  = {result.password_encryption}")
    print(f"    banner_configured    = {result.banner_configured}")
    print(f"    error                = {result.error}")
    print(f"    unrecognized_lines   = {len(result.unrecognized_lines)} lines")

    # Count None fields
    none_count = sum(1 for f in COMPLIANCE_FIELDS if getattr(result, f) is None)
    total = len(COMPLIANCE_FIELDS)
    results_summary.append({
        "vendor": vendor_folder,
        "detected": candidates[0].codec if candidates else "NONE",
        "confidence": candidates[0].confidence if candidates else 0,
        "none_count": none_count,
        "total": total,
        "error": result.error,
    })

# --- Summary table ---
print(f"\n\n{'='*70}")
print(f"  SUMMARY — Full Coverage Report")
print(f"{'='*70}")
print(f"  {'Vendor':<25} {'Detected':<20} {'Conf':>5}  {'Fields':>7}  {'Status'}")
print(f"  {'-'*25} {'-'*20} {'-'*5}  {'-'*7}  {'-'*20}")
for r in results_summary:
    filled = r["total"] - r["none_count"]
    flag = " WARNING >50% None" if r["none_count"] > r["total"] / 2 else " OK"
    status = f"ERROR: {r['error'][:30]}" if r["error"] else f"{filled}/{r['total']} filled{flag}"
    print(f"  {r['vendor']:<25} {r['detected']:<20} {r['confidence']:>5}  {filled}/{r['total']:>5}  {status}")

# --- Phase 3.6 regression check: vendor/codec collision fix ---
print(f"\n{'='*70}")
print(f"  Phase 3.6 regression check — vendor/codec label collision")
print(f"{'='*70}")
cli_path = FIXTURES / "cisco_iosxe_cli" / VENDOR_FILES["cisco_iosxe_cli"]
nc_path = FIXTURES / "cisco_iosxe" / VENDOR_FILES["cisco_iosxe"]
if cli_path.exists() and nc_path.exists():
    cli_result = parse_and_map(cli_path.read_text(encoding="utf-8", errors="replace"))
    nc_result = parse_and_map(nc_path.read_text(encoding="utf-8", errors="replace"))
    print(f"  cisco_iosxe_cli -> vendor={cli_result.vendor!r}, vendor_family={cli_result.vendor_family!r}")
    print(f"  cisco_iosxe     -> vendor={nc_result.vendor!r}, vendor_family={nc_result.vendor_family!r}")
    if cli_result.vendor != nc_result.vendor:
        print(f"  PASS: vendor values are distinct — remediation lookups can key off `vendor` safely")
    else:
        print(f"  FAIL: vendor values still collide — DO NOT proceed to Phase 4 rule pack work")
else:
    print(f"  SKIP: one or both fixture files not found")
