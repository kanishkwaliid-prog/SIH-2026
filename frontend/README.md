# Phase 5.6 — Frontend (Block 1)

Plain HTML/CSS/JS (no build step) implementing the 5-screen flow from
the handoff doc:

1. **Upload** — drag/drop or click to browse, plus sample-config chips
   for demoing without real files, plus an optional vendor override
   dropdown (all 12 codecs from `converter/schema_adapter.py`).
2. **Confirm vendor** — shown automatically when detection confidence
   is below **85%** (`CONFIDENCE_THRESHOLD` in `app.js`). Shows every
   candidate's reason string, plus a manual-pick fallback.
3. **Review unknown lines** — table of `unrecognized_lines` paired
   with AI guesses, submitted as one batch (not per-line popups).
4. **Results** — PASS/FAIL/**UNKNOWN** (styled "COULD NOT DETERMINE"
   in amber, never treated as FAIL), a CIS/NIST framework toggle, a
   PDF download button, and severity + field-checked columns.
5. **What-if panel** — inline on the results screen. Toggle any of
   the 6 `NormalizedConfig` fields on a scratch copy and see
   before/after risk score and the flipped-findings diff live.

## Running it

No build step. Just serve the folder and open `index.html`:

```
cd frontend
python3 -m http.server 8000
# open http://localhost:8000
```

Opening `index.html` directly via `file://` also works, since nothing
here depends on a real backend yet.

## What's real vs. mocked

- `mock-data.js` embeds the **actual** CIS + NIST rule content
  (verbatim `id`/`field`/`expected`/`severity`/`explanation` from
  `rule_packs/*.yaml`), the real 12 vendor codec ids, and a JS port of
  `compliance_engine.evaluate`'s condition-matching logic and
  `risk_score`'s severity weights (critical=3, high=2, medium=1,
  low=0.5) — verified to produce the same numbers as the real Python
  for the sample data in this file.
- Vendor detection, parsing, and AI-classification for the 3 built-in
  sample configs (`edge-sw-1.cfg`, `core-router.junos`,
  `branch-fw.cfg`) are hand-authored fake data, not real codec output
  — there was no live backend to call yet.
- Uploading your **own** file skips real vendor detection (no codecs
  running in the browser) and always routes to the vendor-confirmation
  screen at low confidence, so the flow stays honest about what it
  can't actually do yet rather than pretending to detect real syntax.
- "Download PDF report" builds an HTML preview styled identically to
  `report_generator.generator.generate_pdf()`'s real output (same
  section order, same PASS/FAIL/UNKNOWN colors) and calls
  `window.print()` — it does not call the real ReportLab generator.

## Wiring to the real FastAPI backend (Phase 8)

Every place that stands in for a real backend call is commented
`// MOCK CALL: <real_module.real_function>` in `app.js`. Swapping to
real `fetch()` calls should only touch those call sites and
`mock-data.js` (which gets deleted wholesale) — the screen/state
logic around them shouldn't need to change.

## Verified

Full flow was run headlessly (Puppeteer + chrome-headless-shell) for
both the high-confidence-skip path and the low-confidence
vendor-confirmation path, across both frameworks, including live
what-if score deltas (checked against `risk_score`'s weights by hand)
and the PDF-preview trigger. Not covered: real browser matrix testing
(only Chromium was available in the build sandbox) and real file
uploads with real vendor syntax (no codecs available client-side).
