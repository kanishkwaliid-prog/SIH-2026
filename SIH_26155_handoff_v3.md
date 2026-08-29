# SIH 26155 — Handoff: Current State + Remaining Phase Prompts (v3)

Status as of this handoff: **Phases 1–6 are done and verified against
real modules.** Phases 5.5 (`report_generator/`) and 6 (`whatif/`) were
originally built against a local stub of `shared/schema.py` and
`compliance_engine/evaluate.py` — the CRITICAL FIRST STEP reconciliation
from v2 of this doc has now been completed (see "RECONCILIATION LOG"
below for exactly what changed) and both test suites pass against the
real modules. No stub imports remain anywhere in the repo.

Use this document + the attached zip to continue in whatever tool
you're on next. Give the tool this whole file plus the zip; it has
everything needed to continue without re-deriving context.

---

## RECONCILIATION LOG (v2 → v3, schema fixes applied)

Two field-name mismatches were found between the assumed schema (used
to build Phase 5.5/6) and the real `shared/schema.py` — both were
one-line-per-occurrence fixes, no redesign needed, exactly as v2
anticipated:

- `Finding.field` → real field is `Finding.field_checked`. Fixed in
  `report_generator/generator.py` (3 occurrences) and
  `report_generator/explain.py` (2 occurrences).
- `DeviceInfo.serial` → real field is `DeviceInfo.serial_number`.
  Fixed in `report_generator/generator.py` (1 occurrence).
- `NormalizedConfig`'s 6 fields and `ComplianceReport`'s shape matched
  the original assumption exactly, as v2 predicted (high confidence).
- Additionally: the real `Finding` model requires `expected` and
  `actual` (str, no default) which the stub hadn't modeled. Test
  fixtures in `test_generator.py` were updated to supply them — this
  doesn't affect `report_generator`/`whatif` source code, only test
  data construction.
- `whatif/simulator.py` itself needed no changes — it never inspects
  `rule_pack`'s internal shape, only passes it through to
  `evaluate_config()`. Its test file's `RULE_PACK` fixture was
  rewritten from a flat tuple-list stub to the real dict-with-`rules`
  shape (matching `rule_packs/*.yaml`) that `evaluate_config()`
  actually expects.
- `_test_stubs` imports were removed from both test files; they now
  import directly from the real `shared.schema` /
  `compliance_engine.evaluate`.
- All 12 tests (6 in `test_generator.py`, 6 in `test_simulator.py`)
  pass against real modules. A sample PDF was generated and visually
  verified: PASS/FAIL/UNKNOWN color-coding, Device Identification
  table, and Remediation Paths section all render correctly.

---

## CURRENT STATE — read this first, don't skip

### Repo layout that exists right now
```
converter/
  schema_adapter.py       <- detect_vendor(), parse_and_map(), ComplianceResult
  test_cross_vendor.py    <- tests all 12 vendor codecs + Phase 3.6 regression check
  models.py, __init__.py, test_parse.py, test_schema_adapter.py

compliance_engine/
  evaluate.py              <- load_rule_pack(), evaluate_config(), summarize(), risk_score()
  test_evaluate.py          <- end-to-end test through real fixtures

rule_packs/
  cis_network_devices.yaml       <- 8 CIS rules, correct vendor-keyed remediation
  nist_800_53_network_devices.yaml <- 8 NIST 800-53 rules, cross-referenced remediation

shared/
  schema.py                <- DeviceInfo, NormalizedConfig, Finding, ComplianceReport
                               (the contract every block reads/writes)

ai_fallback/                <- Phase 5, done + verified
  memory.py                 <- SQLite (vendor, line_pattern) -> confirmed category
  classify.py                <- Claude API classification, memory-first, never auto-applies
  test_ai_fallback.py

report_generator/            <- Phase 5.5, done, BUT built against stubbed schema (see above)
  generator.py                <- build_findings_rows(), generate_pdf()
  explain.py                  <- LLM plain-English risk explanation per FAIL finding
  test_generator.py            <- 6/6 passing against stub

whatif/                      <- Phase 6, done, BUT built against stubbed schema (see above)
  simulator.py                 <- simulate_change()
  test_simulator.py             <- 6/6 passing against stub

netcanon/                  <- untouched clone (reference only, safe to delete once
                               converter/ is confirmed self-sufficient)
```

### Key APIs that already exist — use these, don't rebuild them

**`converter.schema_adapter.parse_and_map(config_text: str) -> ComplianceResult`**
```python
@dataclass
class ComplianceResult:
    vendor: str              # specific codec id, e.g. "cisco_iosxe_cli" -- USE THIS
                              #   for any per-vendor lookup (remediation, etc.)
    codec: str                # same as vendor currently, kept for compat
    vendor_family: str | None # generic label e.g. "cisco_iosxe" -- DISPLAY ONLY,
                              #   never use for remediation/vendor-specific lookups
    confidence: int
    ssh_enabled: bool | None
    telnet_enabled: bool | None
    session_timeout_seconds: int | None
    logging_enabled: bool | None
    password_encryption: str | None
    banner_configured: bool | None
    unrecognized_lines: list[str]
    error: str | None
    def to_dict(self) -> dict: ...
```
12 vendors supported: `arista_eos`, `aruba_aoscx`, `aruba_aoss`,
`cisco_iosxe` (NETCONF -- interfaces only, no compliance fields, this
is correct/expected), `cisco_iosxe_cli`, `cisco_iosxr`, `cisco_nxos`,
`fortigate_cli`, `juniper_junos`, `mikrotik_routeros`, `opnsense`,
`vyos`.

**`compliance_engine.evaluate` module:**
```python
load_rule_pack(path) -> dict
evaluate_config(config: NormalizedConfig, vendor: str, rule_pack: dict,
                 cross_reference_pack: dict | None = None) -> list[Finding]
summarize(findings: list[Finding]) -> dict   # {"PASS": n, "FAIL": n, "UNKNOWN": n}
risk_score(findings: list[Finding]) -> float # weighted: critical=3, high=2, medium=1, low=0.5
```
**`Finding.status` has THREE values: `"PASS" | "FAIL" | "UNKNOWN"`.**
UNKNOWN means the source config didn't contain enough info to check
that rule — never treat UNKNOWN as FAIL anywhere (frontend, report,
what-if diff). This is load-bearing across every phase below.

**`shared.schema` module (Pydantic models, the cross-block contract):**
`DeviceInfo`, `NormalizedConfig` (6 fields matching ComplianceResult's
compliance fields), `Finding`, `ComplianceReport`.

**`ai_fallback` module (Phase 5):**
```python
# ai_fallback.memory
MemoryStore.check_known_mapping(vendor, line) -> str | None   # category or None
MemoryStore.confirm_classification(vendor, line, category)     # persists forever

# ai_fallback.classify
classify_lines(vendor, unrecognized_lines, memory: MemoryStore) -> list[LineClassification]
LineClassification.to_review_dict() -> {raw_line, ai_guess, confidence, ...}
```
Never auto-applies a guess. Phase 5.6's review screen is the only
thing that calls `confirm_classification()`.

**`report_generator` module (Phase 5.5):**
```python
build_findings_rows(report: ComplianceReport, explain_fn=None) -> list[FindingRow]
generate_pdf(report: ComplianceReport, output_path, explain_fn=None) -> str  # path to PDF
```
`explain_fn` is injectable (same pattern as `ai_fallback.classify`'s
`api_call_fn`) — defaults to a real Claude call, tests inject a fake.
LLM explanation is requested ONLY for FAIL findings; if it fails, the
PDF still generates (remediation text is independent of it).

**`whatif` module (Phase 6):**
```python
simulate_change(base_config: NormalizedConfig, overrides: dict, vendor: str,
                 rule_pack: dict, cross_reference_pack: dict | None = None) -> dict
# -> {"before_score": float, "after_score": float,
#     "findings_diff": [{"rule_id", "before_status", "after_status"}, ...]}
```
Never mutates `base_config`. `findings_diff` only lists rules whose
status actually flipped (PASS/FAIL/UNKNOWN → different state).

### Known gaps / honest caveats to carry forward
- **Phase 5.5/6 schema assumption** — see CRITICAL FIRST STEP above.
  Do not skip this.
- Remediation CLI in the rule packs is only high-confidence for:
  `cisco_iosxe_cli`, `cisco_iosxr`, `cisco_nxos`, `juniper_junos`,
  `arista_eos`, `vyos`. Entries for `mikrotik_routeros`,
  `fortigate_cli`, `aruba_aoscx`, `aruba_aoss`, `opnsense` are marked
  `NEEDS-VERIFICATION` in the YAML comments — verify against real
  vendor docs before demoing those vendors, don't present as-is.
- `rule_packs/cis_network_devices.yaml`'s `CIS-4.2.1` rule has no
  `fortigate_cli` remediation entry at all (caught by the Phase 4
  test — it correctly returns "no remediation" rather than guessing,
  but it's a content gap worth filling).
- Phase 5.6 (frontend) hasn't been started yet — see below.
- `report_generator` uses ReportLab, not WeasyPrint (avoids a system
  library dependency; the handoff doc allowed either). If you'd
  rather have HTML/CSS templating for easier frontend-designer
  iteration, that's a valid reason to swap it out later, but don't do
  it just for its own sake — ReportLab output is already verified to
  render correctly.

---

## SHARED CONTEXT (prepend to every prompt below)

This is our SIH 2026 (PS 26155) project repo. It has 6 teammate
branches off `main`, plus a 7th branch `netcanon-integration` where we
cloned `netcanon/netcanon` (MIT licensed) and are repurposing its
parser/codec layer. **All work happens on `netcanon-integration`
only** — do not touch `main` or any teammate's branch.

Phases 1–5, 5.5, and 6 are complete (5.5/6 pending the schema
reconciliation above): vendor detection + parsing for 12 codecs
(`converter/schema_adapter.py`), a compliance rule evaluation engine
with two rule packs, CIS and NIST 800-53
(`compliance_engine/evaluate.py`, `rule_packs/*.yaml`), an AI-assisted
unknown-line classifier with persistent memory (`ai_fallback/`), a PDF
report generator (`report_generator/`), and a what-if risk simulator
(`whatif/`). The shared data contract is `shared/schema.py`. Read the
CURRENT STATE section above for exact APIs before writing any new
code — reuse existing functions rather than re-deriving similar logic.

---

## PHASE 5.6 — Frontend (Block 1) — DONE (built plain HTML/CSS/JS)

Built in `frontend/` (`index.html` + `styles.css` + `mock-data.js` +
`app.js` + `README.md`), backend mocked per the spec below. All 5
screens implemented and verified with a headless-browser run
(Puppeteer/chrome-headless-shell) covering both the high-confidence
auto-continue path and the low-confidence vendor-confirmation path,
CIS↔NIST framework switching, live what-if score deltas (hand-checked
against `risk_score`'s severity weights), and the PDF-preview trigger.
`mock-data.js` embeds the real CIS/NIST rule content and a JS port of
`compliance_engine.evaluate`'s condition-matching + `risk_score` logic
— see `frontend/README.md` for exactly what's real vs. mocked and how
to wire in the real FastAPI backend at Phase 8 (every mock call site
is tagged `// MOCK CALL: <real_module.real_function>` in `app.js`).
Not yet done: real per-vendor config parsing in the browser (no codecs
client-side, so uploads of real files fall back to a low-confidence
placeholder rather than a real detection) — this is expected to
resolve naturally once Phase 8 wires the real backend in.

Original spec, for reference:
1. Upload screen — single or bulk config upload, optional vendor
   dropdown (the 12 supported vendors from `converter/schema_adapter.py`).
2. Vendor confirmation screen — shown when
   `ComplianceResult.confidence` is below some threshold (pick ~85 as
   a starting point, tune later); show filename, best guess
   (`ComplianceResult.vendor`), and a reason string (you'll need to
   expose `VendorCandidate.reason` from `detect_vendor()` through the
   API for this).
3. "Review unknown lines" screen — table of
   `ComplianceResult.unrecognized_lines`, paired with
   `ai_fallback.classify`'s guesses (`LineClassification.to_review_dict()`
   shape: `{raw_line, ai_guess, confidence}`), submitted as a batch
   confirm/correct (not one popup per line). On confirm, call
   `ai_fallback.memory.MemoryStore.confirm_classification()` — this is
   the only thing allowed to persist a guess.
4. Results screen — findings table showing PASS/FAIL/**UNKNOWN**
   (three states, not two, styled per `report_generator`'s color
   convention: PASS green, FAIL red, UNKNOWN amber/"could not
   determine") with severity, plus a PDF download link
   (`report_generator.generator.generate_pdf()`'s output).
5. What-if panel — expose `whatif.simulator.simulate_change()` as an
   interactive panel on the results screen: let the user toggle a
   field (e.g. flip `telnet_enabled`) and show the projected
   `before_score`/`after_score`/`findings_diff` live, without touching
   the real stored config.
Mock the backend API with fake JSON shaped like `ComplianceReport`
first; wire to a real FastAPI backend once confirmed stable.

---

## PHASE 7 — Snapshot & revert

Look at how Netcanon's `netcanon/collectors/` stores pulled/backed-up
configs (versioned by hostname + timestamp) and adapt that same
pattern:
1. Before any remediation is actually applied to a real device config,
   snapshot the current config with a timestamp using Netcanon's
   existing storage pattern.
2. After remediation, re-parse (`parse_and_map()`) and re-evaluate
   (`evaluate_config()` + `risk_score()`) to get a fresh score.
3. If the new risk score isn't lower than the pre-change snapshot's
   score, prompt "risk not reduced — revert?"
4. On confirm, restore from the snapshot. Keep snapshot history, don't
   overwrite old ones.
Write as `snapshot_manager.py`: `save_snapshot()`,
`get_latest_snapshot()`, `evaluate_risk_delta()`, `revert_to_snapshot()`.

**Scope check before building this**: confirm whether your project
actually pushes config changes to a real/simulated device, or only
ever produces a report + suggested CLI. If it's report-only, "revert"
means reverting the locally generated recommended-config file, not a
live device — decide this before building Phase 7 so the scope
matches reality.

---

## PHASE 8 — Integration pass

Wire everything into one pipeline: upload → `parse_and_map()` →
`ai_fallback` AI fallback for `unrecognized_lines` → human confirm →
`evaluate_config()` against both rule packs → `report_generator` PDF →
`whatif` what-if panel on the results screen → Phase 7 snapshot/revert
after any applied remediation. Test end-to-end with real fixtures
across several vendors. Confirm every human-confirmation screen
actually blocks auto-apply (vendor guess, unknown-line review, revert
prompt).

---

## PHASE 9 — Attribution & submission prep

Add `THIRD_PARTY_NOTICES.md` crediting Netcanon (MIT licensed,
github.com/netcanon/netcanon) for the codec/parsing layer and the
snapshot/backup storage pattern. In the README/PPT, state plainly
what's original: the compliance rule engine (CIS + NIST packs, UNKNOWN
handling), the AI-assisted unknown-line learning loop with persistent
memory, the what-if risk simulator, the snapshot/revert safety net,
and the dual-audience PDF report generator with the deterministic
CLI / LLM-explanation separation. Keep this factual and short.
