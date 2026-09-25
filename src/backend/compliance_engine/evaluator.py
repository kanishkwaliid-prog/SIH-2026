#!/usr/bin/env python3
"""Block 3 — CIS compliance evaluator.

Loads a YAML rule pack and evaluates it against Block 2 converter JSON.
Null / missing fields are NOT_EVALUATED (never silently skipped).
Empty config {} (unrecognized vendor) is evaluated with a warning.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from .audit_log import log_scan_event

RULES_DIR = Path(__file__).resolve().parent / "rules"
RULE_PACK_PATH = RULES_DIR / "cis_rules.yaml"
RULE_PACK_FILES = (
    "cis_rules.yaml",
    "nist_rules.yaml",
    "stig_rules.yaml",
    "rbi_rules.yaml",
    "sebi_rules.yaml",
    "iso27001_rules.yaml",
)
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

JSON_FINDING_KEYS = (
    "rule_id",
    "framework",
    "status",
    "severity",
    "explanation",
    "remediation_cli",
)


def load_rule_pack(path: Path | str | None = None) -> tuple[list[dict[str, Any]], str]:
    """Load one YAML rule pack by path (CIS, NIST, STIG, RBI, SEBI, or ISO27001).

    Each returned rule dict is tagged with a ``framework`` key from the file.
    """
    pack_path = Path(path) if path else RULE_PACK_PATH
    with pack_path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    framework = data.get("framework") or "CIS"
    rules: list[dict[str, Any]] = []
    for rule in data.get("rules") or []:
        tagged = dict(rule)
        tagged["framework"] = framework
        rules.append(tagged)
    return rules, framework


def load_all_rule_packs(rules_dir: Path | str | None = None) -> list[dict[str, Any]]:
    """Load CIS, NIST, STIG, RBI, SEBI, and ISO27001 packs into one list; each rule is tagged with framework."""
    base = Path(rules_dir) if rules_dir else RULES_DIR
    combined: list[dict[str, Any]] = []
    for filename in RULE_PACK_FILES:
        rules, _framework = load_rule_pack(base / filename)
        combined.extend(rules)
    return combined


FRAMEWORK_FILE_MAP = {
    "CIS": "cis_rules.yaml",
    "NIST": "nist_rules.yaml",
    "STIG": "stig_rules.yaml",
    "RBI": "rbi_rules.yaml",
    "SEBI": "sebi_rules.yaml",
    "ISO27001": "iso27001_rules.yaml",
}


def load_selected_rule_packs(frameworks: list[str], rules_dir: Path | str | None = None) -> list[dict[str, Any]]:
    """Load only the rule packs the user selected, e.g. ['CIS', 'NIST']."""
    base = Path(rules_dir) if rules_dir else RULES_DIR
    combined: list[dict[str, Any]] = []
    for fw in frameworks:
        filename = FRAMEWORK_FILE_MAP.get(fw.upper())
        if not filename:
            continue
        rules, _ = load_rule_pack(base / filename)
        combined.extend(rules)
    return combined


def _norm(value: Any) -> Any:
    if isinstance(value, str):
        return value.strip().lower()
    if isinstance(value, bool):
        return value
    return value


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def condition_holds(actual: Any, condition: Any) -> bool:
    """Return True when `actual` satisfies every clause in the condition (AND)."""
    if not isinstance(condition, dict) or not condition:
        raise ValueError(f"Rule condition must be a non-empty mapping, got {type(condition)!r}")

    actual_n = _norm(actual)
    numeric = _as_number(actual)
    numeric_ops = {"lte", "gte", "lt", "gt"}
    known = {"equals", "not_equals", "in", "not_in", "excludes", *numeric_ops}
    unknown = set(condition) - known
    if unknown:
        raise ValueError(f"Unsupported condition keys: {sorted(unknown)}")

    clauses: list[bool] = []
    if "equals" in condition:
        clauses.append(actual_n == _norm(condition["equals"]))
    if "not_equals" in condition:
        clauses.append(actual_n != _norm(condition["not_equals"]))
    if "in" in condition:
        clauses.append(actual_n in {_norm(item) for item in condition["in"]})
    if "not_in" in condition:
        clauses.append(actual_n not in {_norm(item) for item in condition["not_in"]})
    if "excludes" in condition:
        banned = {_norm(item) for item in condition["excludes"]}
        if isinstance(actual, list):
            clauses.append(all(_norm(item) not in banned for item in actual))
        else:
            clauses.append(actual_n not in banned)

    if numeric_ops & set(condition):
        if numeric is None:
            return False
        if "lte" in condition:
            clauses.append(numeric <= float(condition["lte"]))
        if "gte" in condition:
            clauses.append(numeric >= float(condition["gte"]))
        if "lt" in condition:
            clauses.append(numeric < float(condition["lt"]))
        if "gt" in condition:
            clauses.append(numeric > float(condition["gt"]))

    if not clauses:
        raise ValueError(f"Unsupported condition: {condition!r}")
    return all(clauses)


def _remediation_cli(rule: dict[str, Any], vendor: str | None, failed: bool) -> str | None:
    if not failed:
        return None
    rem = rule.get("remediation") or {}
    if not isinstance(rem, dict):
        return None
    if vendor and vendor in rem:
        text = rem[vendor]
    else:
        text = None
    if isinstance(text, str):
        return text.strip() or None
    return None


def _frameworks_from_rules(rules: list[dict[str, Any]]) -> list[str]:
    seen: list[str] = []
    for rule in rules:
        framework = rule.get("framework")
        if framework and framework not in seen:
            seen.append(str(framework))
    return seen


def _audit_parser_warnings(
    converter_output_json: dict[str, Any],
    engine_warning: str | None,
    parser_warnings: Any,
) -> list[str] | None:
    """Warnings from our detector/evaluator only — never from a config-claimed field."""
    collected: list[str] = []
    if isinstance(parser_warnings, str) and parser_warnings.strip():
        collected.append(parser_warnings.strip())
    elif isinstance(parser_warnings, (list, tuple)):
        collected.extend(str(item).strip() for item in parser_warnings if str(item).strip())

    device = converter_output_json.get("device") if isinstance(converter_output_json, dict) else None
    if isinstance(device, dict):
        confidence = device.get("detection_confidence")
        if confidence == "low":
            collected.append("vendor detection low confidence")

    if engine_warning:
        collected.append(engine_warning)
    return collected or None


def evaluate_report(
    converter_output_json: dict[str, Any],
    rules: list[dict[str, Any]],
    *,
    raw_file_bytes: bytes | None = None,
    frameworks_used: list[str] | str | None = None,
    session_id: str | None = None,
    parser_warnings: Any = None,
    db_path: str | Path = "audit_log.db",
) -> dict[str, Any]:
    """Evaluate one converter document.

    Returns: {
      "device": {...},
      "findings": [...],
      "warning": None or str,
    }
    """
    device = converter_output_json.get("device") or {}
    if not isinstance(device, dict):
        device = {}
    # Detector output only — never converter_output_json["config"]["vendor"].
    vendor = device.get("vendor")

    config = converter_output_json.get("config")
    warning = None
    if config is None or config == {}:
        warning = (
            "Empty or missing config (unrecognized vendor or parse failure); "
            "rules that need a field are marked NOT_EVALUATED."
        )
        config = {}
    if not isinstance(config, dict):
        warning = "Config is not an object; treating as empty. Rules marked NOT_EVALUATED."
        config = {}

    findings: list[dict[str, Any]] = []
    for rule in rules:
        field = rule["field"]
        actual = config.get(field, None)
        if actual is None:
            status = "NOT_EVALUATED"
            failed = False
        else:
            passed = condition_holds(actual, rule["condition"])
            status = "PASS" if passed else "FAIL"
            failed = not passed

        findings.append(
            {
                "rule_id": rule["id"],
                "framework": rule.get("framework"),
                "status": status,
                "severity": rule.get("severity"),
                "explanation": rule.get("explanation"),
                "remediation_cli": _remediation_cli(rule, vendor, failed),
                "field_checked": field,
                "actual": actual,
            }
        )

    result = {"device": device, "findings": findings, "warning": warning}

    if raw_file_bytes is None:
        print("WARNING: audit log skipped: raw_file_bytes not provided", file=sys.stderr)
        return result

    used = frameworks_used if frameworks_used is not None else _frameworks_from_rules(rules)
    try:
        log_scan_event(
            raw_file_bytes=raw_file_bytes,
            converter_output_json=converter_output_json,
            result=result,
            frameworks_used=used,
            session_id=session_id,
            parser_warnings=_audit_parser_warnings(converter_output_json, warning, parser_warnings),
            db_path=db_path,
        )
    except Exception as exc:
        print(f"WARNING: audit log failed: {exc}", file=sys.stderr)

    return result


def json_report(result: dict[str, Any]) -> dict[str, Any]:
    """Shape expected by the report-generator / frontend mock."""
    findings = [
        {key: finding.get(key) for key in JSON_FINDING_KEYS}
        for finding in result["findings"]
    ]
    return {
        "device": result.get("device") or {},
        "findings": findings,
        "warning": result.get("warning"),
    }


def _summarize(result: dict[str, Any]) -> dict[str, int]:
    counts = {"PASS": 0, "FAIL": 0, "NOT_EVALUATED": 0}
    for finding in result["findings"]:
        status = finding["status"]
        counts[status] = counts.get(status, 0) + 1
    return counts


def format_text_report(result: dict[str, Any]) -> str:
    device = result.get("device") or {}
    hostname = device.get("hostname") or "(no hostname)"
    vendor = device.get("vendor") or "(no vendor)"
    lines = [f"=== {hostname}  vendor={vendor} ==="]
    if result.get("warning"):
        lines.append(f"WARNING: {result['warning']}")
    for finding in result["findings"]:
        actual = finding.get("actual")
        field = finding.get("field_checked")
        lines.append(
            f"  {finding['status']:<15} {finding.get('framework') or '':<6} "
            f"{finding['rule_id']:<16} "
            f"{finding.get('severity', ''):<8} {field}={actual!r}"
        )
    counts = _summarize(result)
    lines.append(
        f"  summary  PASS={counts['PASS']}  FAIL={counts['FAIL']}  "
        f"NOT_EVALUATED={counts['NOT_EVALUATED']}"
    )
    lines.append("")
    return "\n".join(lines)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _fixture_files() -> list[Path]:
    return sorted(FIXTURES_DIR.glob("*.json"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate converter JSON against CIS/NIST/STIG rule packs.")
    parser.add_argument("config_file", nargs="?", help="Path to one converter-output JSON file")
    parser.add_argument("--all", action="store_true", help="Evaluate every file in fixtures/")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Print machine-readable JSON (device + findings + warning)",
    )
    parser.add_argument(
        "--rules",
        default=None,
        help="Load a single YAML rule pack by path (default: all CIS+NIST+STIG packs)",
    )
    args = parser.parse_args(argv)

    if not args.all and not args.config_file:
        parser.error("provide a config JSON path or --all")

    if args.rules:
        rules, _framework = load_rule_pack(args.rules)
    else:
        rules = load_all_rule_packs()

    if args.all:
        paths = _fixture_files()
        if not paths:
            print("No JSON files in fixtures/", file=sys.stderr)
            return 1
        results = []
        for path in paths:
            raw_file_bytes = path.read_bytes()
            doc = json.loads(raw_file_bytes.decode("utf-8"))
            if not isinstance(doc, dict):
                raise ValueError(f"{path} must contain a JSON object")
            result = evaluate_report(
                doc,
                rules,
                raw_file_bytes=raw_file_bytes,
                frameworks_used=_frameworks_from_rules(rules),
            )
            result["_fixture"] = str(path.name)
            results.append(result)
        if args.as_json:
            payload = [
                {**json_report(item), "fixture": item["_fixture"]} for item in results
            ]
            print(json.dumps(payload, indent=2))
        else:
            for item in results:
                print(f"# fixture: {item['_fixture']}")
                print(format_text_report(item), end="")
            totals = {"PASS": 0, "FAIL": 0, "NOT_EVALUATED": 0}
            for item in results:
                for status, count in _summarize(item).items():
                    totals[status] += count
            print(
                f"ALL FIXTURES  PASS={totals['PASS']}  FAIL={totals['FAIL']}  "
                f"NOT_EVALUATED={totals['NOT_EVALUATED']}"
            )
        return 0

    path = Path(args.config_file)
    raw_file_bytes = path.read_bytes()
    doc = json.loads(raw_file_bytes.decode("utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(f"{path} must contain a JSON object")
    result = evaluate_report(
        doc,
        rules,
        raw_file_bytes=raw_file_bytes,
        frameworks_used=_frameworks_from_rules(rules),
    )
    if args.as_json:
        print(json.dumps(json_report(result), indent=2))
    else:
        print(format_text_report(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
