# AI-Powered Vendor-Agnostic Network Compliance Engine

SIH 2026 project — an AI-augmented tool that checks network device
configurations (firewalls, routers, switches) from any vendor against
multiple security frameworks (CIS, NIST, DISA STIG, RBI, SEBI), and
generates a compliance report with pass/fail findings, severity, and
step-by-step vendor-specific remediation. Includes a human-review
consensus layer (staged votes + hash-chained audit log) so no single
person can unilaterally teach the system a wrong answer.

## Team

| Role | Responsibility |
|---|---|
| Frontend | Upload UI, vendor confirmation, unknown-line review, report dashboard |
| Vendor detection + parsers | Signature detection, hardcoded Cisco/Juniper/Palo Alto parsers |
| LLM fallback + review system | Groq-based classification for unknown lines, staged human consensus, hash-chained audit log |
| Compliance engine | Rule evaluation logic, CIS/NIST/STIG/RBI/SEBI rule pack authoring |
| Report generation | PDF report (Simple/Technical view), remediation formatting |

## How the pipeline works

1. **Frontend** — user uploads one or more config files, optionally names
   the vendor, and picks which ruleset(s) to check against
2. **Converter** (`converter/`, `block2b/`) — detects the vendor, converts
   the config into the standard JSON schema (`shared/schema.py`). Falls
   back to an LLM guess (with sensitive values redacted before the API
   call) for anything it doesn't recognize, then to human review.
3. **Human review layer** (`block2b/review_system.py`) — low-confidence
   lines go to a staging table; once enough independent reviewers agree
   (weighted by role), the answer is promoted into permanent memory and
   the promotion is recorded in a hash-chained audit log
4. **Compliance engine** (`compliance_engine/`) — checks the resolved
   JSON against the selected rule pack(s) (CIS/NIST/STIG/RBI/SEBI)
5. **Report generator** (`report_generator/`) — turns findings into a PDF
   with plain-English (Simple View) and technical (Technical View)
   explanations, plus vendor-specific CLI remediation

## Repo structure

api.py                   FastAPI backend -- wires everything below into HTTP endpoints
pipeline.py               Orchestrates Block 2 (detection -> parsing -> LLM fallback)
main.py                    Standalone CLI test script (no server needed)
DESIGN.md                   Design notes for the human-review / hash-chain system

converter/                 Vendor detection + hardcoded parsers (Cisco/Juniper/Palo Alto)
  parsers/                     cisco.py, juniper.py, paloalto.py, dispatch table
  block2a_main.py               Entry point: run_block2a()
  detection.py                    Vendor signature detection

block2b/                    LLM fallback + memory + human review/consensus system
  llm_classifier.py             Groq-based classification, redacts sensitive values first
  memory.py                       Permanent confirmed-line cache
  review_system.py                 Staged voting, promotion threshold, hash-chained audit log
  readme_2b.md                       Notes from Block 2b's original build

compliance_engine/
  evaluator.py                Rule evaluation logic, loads one or several rule packs
  rules/                        cis_rules.yaml, nist_rules.yaml, stig_rules.yaml, rbi_rules.yaml, sebi_rules.yaml
  fixtures/                      Sample converter-output JSON for testing the evaluator alone

report_generator/           PDF report generation (Jinja2 + WeasyPrint)
  report_gen.py
  router.py

frontend/                    Real, wired frontend (not a mockup) -- calls api.py directly
  shared.js                     API calls, session storage, page-to-page routing
  upload_configuration/
  analyzing_configuration/
  vendor_detection_result/
  review_unknown_lines/
  compliance_report_dashboard/    Includes the multi-framework ruleset picker

shared/                       Shared JSON schema (schema.py) + sample configs everyone tests against
tests/                          test_block2a.py, test_classifier.py, test_all_samples.py
legacy_unused/                    Archived early frontend prototype (app.py/app.js) -- kept for reference, not used

## Getting started (local setup)

```bash
git clone <repo-url>
cd <repo-name>
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env          # then fill in your Groq API key
```

If `pip install` complains about a missing system library for PDF
generation (WeasyPrint), install these first:
```bash
brew install pango cairo gdk-pixbuf libffi     # macOS
```

## Running it

You need two things running at once, in two terminals:

```bash
# Terminal 1 -- backend API
source venv/bin/activate
uvicorn api:app --reload --port 8000
```

```bash
# Terminal 2 -- frontend
cd frontend
python3 -m http.server 5500
```

Then open `http://localhost:5500/upload_configuration/` in your browser.
(Opening the HTML files directly by double-clicking them will not work
correctly -- serve them via the command above.)

## Testing without the frontend

```bash
python3 main.py                                  # runs one fixture through Block 3 + 4 directly
python3 tests/test_block2a.py <config-file>        # test detection + parsing alone
python3 tests/test_classifier.py                    # test the LLM classifier's accuracy
```

## Branching workflow

- Block-based branches (`block2a-parser`, `block3-compliance`, etc.) are
  retired -- all blocks are merged and working together on `main`.
- New work happens on feature branches created off `main`:
  `git checkout main && git pull && git checkout -b my-feature`
- Commit and push regularly, not just once at the end
- Open a Pull Request into `main` when a feature works; get one teammate
  to review before merging
- If you need to change `shared/schema.py`, message the team first —
  every block depends on it

## Environment variables

Copy `.env.example` to `.env` and fill in:

```
GROQ_API_KEY=your_key_here
```

Never commit `.env` — it's already in `.gitignore`. If a key is ever
accidentally committed, treat it as compromised: revoke and rotate it
immediately, regardless of whether the repo is public or private.

## Deliverables checklist

- [x] Source code (this repo)
- [x] README with setup instructions (this file)
- [ ] Architecture document (max 2 pages) — `docs/architecture.pdf`
- [ ] Demo video (max 2 minutes) — link in `docs/demo_video.md`
- [ ] Technical presentation (max 5 slides) — `docs/presentation.pptx`