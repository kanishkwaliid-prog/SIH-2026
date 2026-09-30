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
source vendor. Ten vendors are supported directly: Cisco, Juniper, and
Palo Alto are fully parsed; Fortinet, Arista, Huawei, MikroTik, Check
Point, Netgate pfSense, and SONiC are experimentally supported, with
some fields intentionally left unevaluated where vendor syntax isn't yet
confirmed. For any other vendor, or any line a parser doesn't recognize,
a locally-trained classifier makes a first-pass guess; only when it's
unsure does the system escalate to an LLM (sensitive values redacted
before the API call). Any classification below full confidence then goes
through a staged human-review process — multiple independent reviewers,
weighted by role, must agree before an answer is trusted for future
scans, and every promotion is recorded in a hash-chained, tamper-evident
audit log. The resolved configuration is checked against one or more
security frameworks (CIS, NIST, STIG, RBI, SEBI, ISO 27001) and compiled
into a report — PDF, JSON, CSV, or Markdown — with severity-rated
findings and vendor-specific CLI remediation. Access to the tool itself
is organization-scoped, with TOTP-based 2FA and role-based permissions,
and every action a user takes is appended to its own hash-chained
activity log.

## 4. Key Features

- **Vendor-agnostic ingestion** — auto-detects vendor from config
  structure (with human override); bulk upload of single or multiple
  config files in one pass, across 10 directly-supported vendors
- **Local ML pre-classifier** — a locally-trained model attempts to
  classify unrecognized config lines before any cloud LLM call is made,
  reducing API usage and keeping more data on-device
- **AI-assisted learning loop** — anything the local classifier can't
  confidently place is classified by an LLM, then verified through
  weighted human consensus before being trusted permanently, so no
  single reviewer can teach the system a wrong answer
- **Privacy-conscious LLM use** — IPs, passwords, and community strings
  are redacted before any config text is sent to the cloud LLM
- **Multi-framework compliance** — CIS, NIST, STIG, RBI, SEBI, and
  ISO 27001 rule packs, with a picker to choose which framework(s) to
  evaluate against
- **Multi-format reporting** — Simple View (plain-English) and Technical
  View (field-level detail + exact CLI remediation) in one report,
  exportable as PDF, JSON, CSV, or Markdown
- **Secure multi-tenant accounts** — signup/login, TOTP-based 2FA with
  backup codes, and role-based access (admin/senior engineer/engineer/
  viewer), scoped per organization
- **Tamper-evident audit trails** — every promoted training decision
  and every login/upload/confirmation/evaluation is hash-chained (one
  chain for training consensus, one for account activity, both sharing
  the same hash logic), so both histories are independently verifiable
  via `GET /audit`

## 5. Technology Stack

- **Backend:** Python, FastAPI
- **AI/LLM:** Groq API (`openai/gpt-oss-120b`)
- **Storage:** SQLite (confirmed-line memory, staged review votes,
  hash-chained audit log)
- **Auth:** PyJWT, argon2-cffi (password hashing), PyOTP + qrcode (TOTP 2FA)
- **Local classifier:** scikit-learn + joblib
- **Rule packs:** PyYAML (CIS/NIST/STIG/RBI/SEBI/ISO 27001)
- **Report generation:** Jinja2 + WeasyPrint (PDF)
- **Frontend:** HTML, CSS, vanilla JavaScript (Tailwind design tokens)

## 6. Architecture

See [docs/architecture.md](docs/architecture.md) for the full breakdown.

```
User uploads config(s)
        |
        v
Sign-in (email + password, optional TOTP 2FA)
        |
        v
Frontend (upload -> vendor confirm -> unknown-line review -> report)
        |
        v
Backend API (FastAPI) -- every action logged to a hash-chained activity log
        |
        v
Vendor detection + parsers (Cisco/Juniper/Palo Alto fully supported;
        Fortinet/Arista/Huawei/MikroTik/Check Point/Netgate pfSense/SONiC experimental)
        |
        v
Local ML classifier (first pass) --> LLM fallback (redacted, cloud) -->
        |   staged human review --> hash-chained promotion audit log
        v
Normalized JSON config
        |
        v
Compliance engine (CIS / NIST / STIG / RBI / SEBI / ISO 27001 rule packs)
        |
        v
Report (PDF / JSON / CSV / Markdown -- Simple + Technical view, vendor-specific remediation)
```

## 7. Repository Structure

```
SIH-2026/
├── README.md
├── requirements.txt
├── .env.example
├── dev-notes/                    Internal build log, design notes, and phase-by-phase
│   ├── CHANGES_BLOCK1.md           changes — not required reading, kept for process transparency
│   ├── DESIGN.md
│   └── PROGRESS.md
├── docs/
│   ├── architecture.md
│   ├── architecture.pdf
│   └── auth_decisions.md          Auth/2FA/RBAC/activity-log design decisions + API shapes
├── submission/
│   ├── PRESENTATION.md
│   └── DEMO.md
├── assets/
│   └── screenshots/
└── src/
    ├── frontend/                    Static HTML/CSS/JS -- calls api.py directly, no mock data
    │   shared.js                        API calls, session storage, routing, VENDORS table, escapeHtml()
    │   auth/login/, auth/signup/          Sign-in / organization signup
    │   account/security/                  2FA enroll/disable, backup codes
    │   admin/users/                       Team management (admin only)
    │   admin/activity/                    Hash-chained activity log viewer (admin/senior engineer)
    │   upload_configuration/
    │   analyzing_configuration/
    │   vendor_detection_result/
    │   review_unknown_lines/
    │   compliance_report_dashboard/       Multi-framework ruleset picker, PDF/JSON/CSV/MD export
    │   rulesets/                          Framework + vendor reference page
    │   legal/                             Privacy, Terms, Help
    │
    └── backend/
        api.py                      FastAPI backend -- wires everything below into HTTP endpoints
        pipeline.py                  Orchestrates vendor detection -> parsing -> local classifier -> LLM fallback
        main.py                       Standalone CLI test script (no server needed)
        activity_log.py               Hash-chained activity log (shared hash fn with review_system); GET /audit

        auth/                          Accounts, 2FA, RBAC
          routes.py                        Signup/login, TOTP enroll/verify/disable, backup codes
          admin_routes.py                    Team management, role changes, admin 2FA reset
          deps.py                              require_permission(...) — applied to every endpoint
          store.py                              Account/org storage helpers
          security.py, lockout.py, totp.py         Password hashing, login lockout, TOTP logic
          config.py                             JWT secret loading/validation
          test_*.py, conftest.py                  Run with: pytest auth/ -q

        converter/                    Vendor detection + parsers
          parsers/                        cisco.py, juniper.py, paloalto.py (fully supported)
                                            fortinet.py, arista.py, huawei.py, mikrotik.py,
                                            checkpoint.py, netgate_pfsense.py, sonic.py (experimental)
          block2a_main.py                  Entry point: run_block2a()
          detection.py                       Vendor signature detection (10 vendors)
          device_details.py                    Hostname/model/OS/IP extraction for the report

        block2b/                       Local classifier + LLM fallback + memory + human review
          prefilter.py                     Locally-trained classifier, tried before any cloud call
          train_prefilter.py                  Model training script
          prefilter_model.joblib                Trained model
          prefilter_training_data.csv,         Training/eval data
          prefilter_holdout.csv, real_eval.csv
          new_configs/                          Real + synthetic sample configs used for training
          llm_classifier.py                Groq-based classification, redacts sensitive values first
          redaction.py                        Sensitive-value redaction before any cloud call
          memory.py                          Permanent confirmed-line cache
          review_system.py                    Staged voting, promotion threshold, hash-chained audit log
          test_*.py                              Classifier + redaction tests

        compliance_engine/
          evaluator.py                   Rule evaluation logic, loads one or several rule packs
          rules/                           cis_rules.yaml, nist_rules.yaml, stig_rules.yaml,
                                             rbi_rules.yaml, sebi_rules.yaml, iso27001_rules.yaml
          vendor_remediation.yaml           Shared per-vendor fix-command notebook (fallback when a
                                              rule has no vendor-specific remediation of its own)
          fixtures/                         Sample converter-output JSON for testing the evaluator alone

        report_generator/               PDF/JSON/CSV/Markdown report generation (Jinja2 + WeasyPrint)
        shared/                          Shared JSON schema + sample configs
        simulate_reviewers.py           Dev script for exercising the review-consensus flow
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
cp .env.example .env          # then fill in GROQ_API_KEY, JWT_SECRET, DEMO_PASSWORD
```

Generate a `JWT_SECRET` with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
The backend refuses to start without one.

If PDF generation fails to install, install these system libraries first:
```bash
brew install pango cairo gdk-pixbuf libffi     # macOS
```

## 12. Run

Two terminals, run at the same time:

```bash
# Terminal 1 -- backend API
source venv/bin/activate
cd src/backend
uvicorn api:app --reload --port 8000
```

```bash
# Terminal 2 -- frontend
cd src/frontend
python3 -m http.server 5500
```

Open `http://localhost:5500/upload_configuration/` in your browser. You'll be
sent to the sign-in page first.

**Demo accounts** (created at startup when `DEMO_PASSWORD` is set, all using that password): `admin@`, `senior@`, `engineer@` and `viewer@` at `alpha.demo` and `beta.demo` -- e.g. `engineer@alpha.demo`. Or create a new organization from the sign-in page.

Auth design and API shapes: `docs/auth_decisions.md`.

**Tests:** `cd src/backend && pytest auth/ -q`

## 13. Future Scope

- **Live device polling** — pulling configs directly from devices via
  SSH (Netmiko/NAPALM) rather than trusting an uploaded file, closing
  the file-authenticity gap that no upload-based tool can fully solve
- **Local/on-prem LLM option** — for organizations that can't send any
  config data to a third-party API, even redacted
- **Broader parser coverage for the 7 experimental vendors** — Fortinet,
  Arista, Huawei, MikroTik, Check Point, Netgate pfSense, and SONiC are
  auto-detected and partially checked today; several fields per vendor
  are intentionally left "Not Evaluated" pending confirmed vendor syntax
- **Tighter CORS and a relative API base** — currently permissive/
  hardcoded for local development

## Important

Do not commit `.env`, API keys, or any other credentials. `.env` is
already excluded via `.gitignore`; if a key is ever accidentally
committed, revoke and rotate it immediately.