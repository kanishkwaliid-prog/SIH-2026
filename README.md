# AI-Driven Multi-Vendor Network Security Compliance Auditor

## 1. Project Information

- **Project Title:** AI-Driven Multi-Vendor Network Security Compliance Auditor
- **PS ID:** 26155
- **PS Title:** AI-Driven Multi-Vendor Network Security Compliance Auditor
- **Category:** Software
- **Theme:** Blockchain & Cybersecurity
- **Team Name:** Segmentation Fault

## 2. Problem Statement

Modern enterprise networks run hardware from dozens of vendors, each with
its own proprietary CLI syntax. Organizations must align these devices
with security frameworks like CIS, NIST SP 800-53, and DISA STIGs, but
today this is either done manually (slow, error-prone) or with
expensive, vendor-locked tools that can't adapt to new or unfamiliar
device types. As networks adopt new/white-box hardware, traditional
hardcoded parsers fail outright, since they can't interpret
configuration structures they were never built to recognize.

## 3. Proposed Solution

An AI-augmented, vendor-agnostic compliance engine. Configuration files
are normalized into a standard, vendor-neutral schema regardless of
source vendor. Known vendors (Cisco, Juniper, Palo Alto) are parsed
directly; genuinely unrecognized syntax is classified by an LLM
(sensitive values redacted before the API call), and any classification
below full confidence goes through a staged human-review process —
multiple independent reviewers, weighted by role, must agree before an
answer is trusted for future scans, and every promotion is recorded in a
hash-chained, tamper-evident audit log. The resolved configuration is
then checked against one or more security frameworks (CIS, NIST, STIG,
RBI, SEBI) and compiled into a PDF report with severity-rated findings
and vendor-specific CLI remediation.

## 4. Key Features

- **Vendor-agnostic ingestion** — auto-detects vendor from config
  structure (with human override), no hardcoded vendor list required
- **AI-assisted learning loop** — unrecognized syntax is classified by
  an LLM, then verified through weighted human consensus before being
  trusted permanently, so no single reviewer can teach the system a
  wrong answer
- **Tamper-evident audit trail** — every promoted training decision is
  hash-chained, so the training history is independently verifiable
- **Multi-framework compliance** — CIS, NIST, STIG, RBI, and SEBI rule
  packs, with a picker to choose which framework(s) to evaluate against
- **Privacy-conscious LLM use** — IPs, passwords, and community strings
  are redacted before any config text is sent to the cloud LLM
- **Bulk upload** — single or multiple config files in one pass
- **PDF reporting** — Simple View (plain-English) and Technical View
  (field-level detail + exact CLI remediation) in one report

## 5. Technology Stack

- **Backend:** Python, FastAPI
- **AI/LLM:** Groq API (`openai/gpt-oss-120b`)
- **Storage:** SQLite (confirmed-line memory, staged review votes,
  hash-chained audit log)
- **Rule packs:** PyYAML (CIS/NIST/STIG/RBI/SEBI)
- **Report generation:** Jinja2 + WeasyPrint (PDF)
- **Frontend:** HTML, CSS, vanilla JavaScript (Tailwind design tokens)

## 6. Architecture

See [docs/architecture.md](docs/architecture.md) for the full breakdown.

```
User uploads config(s)
        |
        v
Frontend (upload -> vendor confirm -> unknown-line review -> report)
        |
        v
Backend API (FastAPI)
        |
        v
Vendor detection + hardcoded parsers (Cisco / Juniper / Palo Alto)
        |
        v
LLM fallback (redacted) --> staged human review --> hash-chained
        |   promotion on consensus                  audit log
        v
Normalized JSON config
        |
        v
Compliance engine (CIS / NIST / STIG / RBI / SEBI rule packs)
        |
        v
PDF report (Simple + Technical view, vendor-specific remediation)
```

## 7. Repository Structure

```
api.py                   FastAPI backend -- wires everything below into HTTP endpoints
pipeline.py               Orchestrates vendor detection -> parsing -> LLM fallback
main.py                    Standalone CLI test script (no server needed)
DESIGN.md                   Design notes for the human-review / hash-chain system

converter/                 Vendor detection + hardcoded parsers
  parsers/                     cisco.py, juniper.py, paloalto.py
  block2a_main.py               Entry point: run_block2a()
  detection.py                    Vendor signature detection

block2b/                    LLM fallback + memory + human review/consensus system
  llm_classifier.py             Groq-based classification, redacts sensitive values first
  memory.py                       Permanent confirmed-line cache
  review_system.py                 Staged voting, promotion threshold, hash-chained audit log

compliance_engine/
  evaluator.py                Rule evaluation logic, loads one or several rule packs
  rules/                        cis_rules.yaml, nist_rules.yaml, stig_rules.yaml, rbi_rules.yaml, sebi_rules.yaml
  fixtures/                      Sample converter-output JSON for testing the evaluator alone

report_generator/           PDF report generation (Jinja2 + WeasyPrint)

frontend/                    Wired frontend -- calls api.py directly, no mock data
  shared.js                     API calls, session storage, page-to-page routing
  upload_configuration/
  analyzing_configuration/
  vendor_detection_result/
  review_unknown_lines/
  compliance_report_dashboard/    Multi-framework ruleset picker

shared/                       Shared JSON schema + sample configs
docs/                            architecture.md, architecture.pdf
submission/                       PRESENTATION.md, DEMO.md
assets/screenshots/                 App screenshots for submission
```

## 8. Final Presentation

See [submission/PRESENTATION.md](submission/PRESENTATION.md).

## 9. Demo Video

See [submission/DEMO.md](submission/DEMO.md).

## 10. Screenshots / Prototype Photos

See [assets/screenshots/](assets/screenshots/).

## 11. Installation

```bash
git clone <YOUR_REPOSITORY_URL>
cd SIH-2026
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env          # then fill in your Groq API key
```

If PDF generation fails to install, install these system libraries first:
```bash
brew install pango cairo gdk-pixbuf libffi     # macOS
```

## 12. Run

Two terminals, run at the same time:

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

Open `http://localhost:5500/upload_configuration/` in your browser.

## 13. Future Scope

- **Multi-tenant access control** — separate dashboards per organization,
  2FA, and role-based access control (scoped out of this prototype due
  to time; a role-lookup mechanism already exists for the human-review
  layer and could be extended)
- **Live device polling** — pulling configs directly from devices via
  SSH (Netmiko/NAPALM) rather than trusting an uploaded file, closing
  the file-authenticity gap that no upload-based tool can fully solve
- **Local/on-prem LLM option** — for organizations that can't send any
  config data to a third-party API, even redacted
- **Expanded vendor + framework coverage** — additional hardcoded
  parsers and rule packs as new vendors/standards are requested

## Important

Do not commit `.env`, API keys, or any other credentials. `.env` is
already excluded via `.gitignore`; if a key is ever accidentally
committed, revoke and rotate it immediately.