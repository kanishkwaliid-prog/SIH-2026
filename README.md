# SIH 26155 — Network Compliance Audit Toolkit

A vendor-agnostic network device compliance auditor: parse configs
from 12 network vendors, evaluate them against CIS and NIST 800-53
rule packs, generate PDF reports with plain-English remediation
explanations, and simulate the risk impact of proposed config changes
before applying them.

Built for Smart India Hackathon 2026 (Problem Statement 26155).

## Status

| Phase | What | Status |
|---|---|---|
| 1–3 | Vendor parsing / schema adapter (`converter/`) | ⚠️ see **Known issues** below |
| 4 | Compliance rule engine (`compliance_engine/`, `rule_packs/`) | ✅ done, verified |
| 5 | AI-assisted unknown-line classifier (`ai_fallback/`) | ✅ done, verified |
| 5.5 | PDF report generator (`report_generator/`) | ✅ done, verified against real schema |
| 5.6 | Frontend (`frontend/`) | ✅ done, mocked backend, verified end-to-end |
| 6 | What-if risk simulator (`whatif/`) | ✅ done, verified against real schema |
| 7 | Snapshot & revert | Not started |
| 8 | Full pipeline integration | Not started |
| 9 | Attribution & submission prep | Not started |

See `SIH_26155_handoff_v3.md` for the detailed phase-by-phase history
and the exact reconciliation log of what was fixed between the mocked
and real schema.

## Known issues

- **`converter/schema_adapter.py` imports `converter.netcanon_migration.codecs.registry`,
  which is not present in this repo.** That package (the actual
  per-vendor parsing codecs for all 12 supported vendors) was never
  delivered in any of the source zips this repo was assembled from —
  only `schema_adapter.py` itself and `test_cross_vendor.py` were
  provided. As a result, `converter/schema_adapter.py` cannot
  currently be imported, and `converter/test_cross_vendor.py` will
  fail to collect. Every other module (`compliance_engine`, `shared`,
  `ai_fallback`, `report_generator`, `whatif`) imports and runs
  independently of this and is unaffected. **Before relying on live
  vendor detection/parsing, the `netcanon_migration` codec package
  needs to be added** (per the handoff doc, this was migrated from
  `netcanon/netcanon`, MIT licensed).
- `rule_packs/*.yaml` remediation commands are only verified/high-confidence
  for `cisco_iosxe_cli`, `cisco_iosxr`, `cisco_nxos`, `juniper_junos`,
  `arista_eos`, and `vyos`. Entries for `mikrotik_routeros`,
  `fortigate_cli`, `aruba_aoscx`, `aruba_aoss`, and `opnsense` are
  marked `NEEDS-VERIFICATION` in the YAML — confirm against current
  vendor docs before demoing or shipping those vendors.
- `frontend/` runs entirely against mocked data (see
  `frontend/README.md`) — it has not been wired to a real backend yet.

## Repo layout

```
converter/            Vendor detection + parsing -> ComplianceResult
                       (imports a missing codec package -- see Known issues)
compliance_engine/    Rule evaluation engine (evaluate_config, risk_score)
rule_packs/           CIS + NIST 800-53 rule definitions (YAML)
shared/               Pydantic models -- the cross-block data contract
ai_fallback/          AI-assisted classifier for unrecognized config lines,
                       with a persistent per-vendor memory (SQLite)
report_generator/     PDF compliance report generator (ReportLab)
whatif/               Risk-impact simulator for proposed config changes
frontend/             Phase 5.6 UI (plain HTML/CSS/JS, mocked backend)
```

## Setup

Requires Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the test suites (each covers one module independently):

```bash
pytest compliance_engine/test_evaluate.py
pytest ai_fallback/test_ai_fallback.py
pytest report_generator/test_generator.py
pytest whatif/test_simulator.py

# NOTE: this one currently fails to collect -- see Known issues above
pytest converter/test_cross_vendor.py
```

The `ai_fallback` and `report_generator` modules default to real
Claude API calls (`ANTHROPIC_API_KEY` env var required) for
unrecognized-line classification and FAIL-finding explanations
respectively, but both accept an injectable function
(`api_call_fn` / `explain_fn`) — the test suites use fakes and don't
need an API key.

### Frontend

No build step needed:

```bash
cd frontend
python3 -m http.server 8000
# open http://localhost:8000
```

See `frontend/README.md` for what's real vs. mocked in the current
build.

## License

Original code in this repo (compliance rule engine, AI-assisted
unknown-line learning loop, what-if risk simulator, PDF report
generator) is © the SIH 26155 team. The vendor codec/parsing layer
(once added — see Known issues) and the snapshot/backup storage
pattern planned for Phase 7 are adapted from
[Netcanon](https://github.com/netcanon/netcanon) (MIT licensed);
proper attribution is planned for Phase 9 and not yet added to this
repo.
