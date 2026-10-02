# AI-Driven Multi-Vendor Network Security Compliance Auditor

![Home Page](assets/screenshots/home.png)

## 1. Project Information

- **Project Title:** AI-Driven Multi-Vendor Network Security Compliance Auditor
- **PS ID:** 26155
- **PS Title:** AI-Driven Multi-Vendor Network Security Compliance Auditor
- **Category:** Software
- **Theme:** Blockchain & Cybersecurity
- **Team Name:** Segmentation Fault

| Resource | Link |
|---|---|
| GitHub Repository | [kanishkwaliid-prog/SIH-2026](https://github.com/kanishkwaliid-prog/SIH-2026) |
| Demo Video | [Watch on YouTube](https://www.youtube.com/watch?v=amNHwsLx78g) |
| Presentation (PPT) | [Google Drive](https://drive.google.com/drive/folders/1oOA9zceZgk9ZKvUtSgLsa_jGkEyHQTX8?usp=sharing) |
| Architecture Document | [Google Drive](https://drive.google.com/drive/folders/1SJUBmso8XW0OwtMuxsepUmIMRxHzHp3Q?usp=sharing) |

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
Point, Netgate pfSense, and SONiC are experimentally supported. For any
other vendor, or any line a parser doesn't recognize, a locally-trained
classifier makes a first-pass guess, and only when it's unsure does the
system escalate to an LLM (with sensitive values redacted first). Any
classification below full confidence goes through a staged human-review
process before it is trusted, and every promotion is recorded in a
tamper-evident audit log. The resolved configuration is checked against
one or more security frameworks and compiled into a report with
severity-rated findings and vendor-specific CLI remediation. Access is
organization-scoped, with 2FA and role-based permissions.

## 4. Key Features

- **Vendor-agnostic ingestion** — auto-detects vendor from config
  structure (with human override); bulk upload across 10
  directly-supported vendors
- **Local ML pre-classifier** — classifies unrecognized lines on-device
  before any cloud LLM call is made
- **AI-assisted learning loop** — LLM suggestions are verified through
  weighted human consensus before being trusted
- **Privacy-conscious LLM use** — IPs, passwords, and community strings
  are redacted before any config text leaves the machine
- **Multi-framework compliance** — CIS, NIST, STIG, RBI, SEBI, and
  ISO 27001, with a picker to choose which to evaluate against
- **Multi-format reporting** — Simple and Technical views with
  vendor-specific remediation, exportable as PDF, JSON, CSV, or Markdown
- **Secure multi-tenant accounts** — TOTP-based 2FA with backup codes
  and role-based access, scoped per organization
- **Tamper-evident audit trails** — hash-chained logs for training
  decisions and user activity, verifiable via `GET /audit`

## 5. Technology Stack

- **Backend:** Python, FastAPI
- **AI/LLM:** Groq API (`openai/gpt-oss-120b`)
- **Storage:** SQLite
- **Auth:** PyJWT, argon2-cffi, PyOTP + qrcode
- **Local classifier:** scikit-learn + joblib
- **Rule packs:** PyYAML
- **Report generation:** Jinja2 + WeasyPrint (PDF)
- **Frontend:** HTML, CSS, vanilla JavaScript

## 6. Architecture

Full breakdown: [Architecture Document](https://drive.google.com/drive/folders/1SJUBmso8XW0OwtMuxsepUmIMRxHzHp3Q?usp=sharing)

![Architecture Diagram](assets/screenshots/architecture.png)

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
Backend API (FastAPI)
        |
        v
Vendor detection + parsers
        |
        v
Local ML classifier --> LLM fallback (redacted) --> human review
        |
        v
Normalized JSON config
        |
        v
Compliance engine (CIS / NIST / STIG / RBI / SEBI / ISO 27001)
        |
        v
Report (PDF / JSON / CSV / Markdown)
```

## 7. Repository Structure

```
SIH-2026/
├── README.md
├── requirements.txt
├── .env.example
├── assets/
│   └── screenshots/
├── dev-notes/                    Build log and design notes
├── submission/                   Presentation and demo notes
└── src/
    ├── frontend/                   Static HTML/CSS/JS, calls the backend API directly
    │   ├── shared.js                 API calls, session handling, routing
    │   ├── auth/                     Sign-in / organization signup
    │   ├── account/security/         2FA setup and backup codes
    │   ├── admin/                    Team management, activity log viewer
    │   ├── upload_configuration/
    │   ├── analyzing_configuration/
    │   ├── vendor_detection_result/
    │   ├── review_unknown_lines/
    │   ├── compliance_report_dashboard/
    │   ├── rulesets/
    │   └── legal/                    Privacy, Terms, Help
    │
    └── backend/
        ├── api.py                    FastAPI app, wires everything into HTTP endpoints
        ├── pipeline.py               Detection -> parsing -> classifier -> LLM fallback
        ├── activity_log.py           Hash-chained user activity log
        ├── main.py                   Standalone CLI test script
        │
        ├── auth/                     Accounts, 2FA, role-based access
        │   ├── routes.py               Signup/login, 2FA enrollment
        │   ├── admin_routes.py         Team and role management
        │   ├── deps.py                 Permission checks on endpoints
        │   ├── store.py                Account / organization storage
        │   ├── security.py             Password hashing
        │   ├── lockout.py              Login lockout
        │   ├── totp.py                 TOTP logic
        │   └── config.py               JWT secret loading
        │
        ├── converter/                Vendor detection + parsers
        │   ├── detection.py            Vendor signature detection
        │   ├── block2a_main.py         Entry point
        │   └── parsers/                One parser per vendor (10 vendors)
        │
        ├── block2b/                  Local classifier, LLM fallback, memory, review
        │   ├── prefilter.py            Local classifier (tried before any cloud call)
        │   ├── rules_prefilter.py      Rule-based pre-filter
        │   ├── train_prefilter.py      Classifier training script
        │   ├── llm_classifier.py       Groq-based classification
        │   ├── redaction.py            Sensitive-value redaction
        │   ├── memory.py               Confirmed-line cache
        │   └── review_system.py        Staged human review + audit log
        │
        ├── compliance_engine/        Compliance evaluation
        │   ├── evaluator.py            Rule evaluation logic
        │   ├── audit_log.py            Scan audit log
        │   └── rules/                  CIS, NIST, STIG, RBI, SEBI, ISO 27001 (YAML)
        │
        ├── report_generator/
        │   └── report_gen.py         PDF / JSON / CSV / Markdown reports
        └── shared/
            └── schema.py             Common vendor-neutral schema
```

## 8. Final Presentation

[View the presentation (Google Drive)](https://drive.google.com/drive/folders/1oOA9zceZgk9ZKvUtSgLsa_jGkEyHQTX8?usp=sharing)

## 9. Demo Video

[Watch the demo on YouTube](https://www.youtube.com/watch?v=amNHwsLx78g)

## 10. Screenshots / Prototype Photos

**Upload Configuration**

![Upload Configuration](assets/screenshots/home.png)

**Compliance Report Dashboard** (click to watch the demo)

[![Demo Video](assets/screenshots/demo-thumbnail.png)](https://www.youtube.com/watch?v=amNHwsLx78g)

## 11. Installation

```bash
git clone https://github.com/kanishkwaliid-prog/SIH-2026.git
cd SIH-2026
```

**macOS / Linux**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then fill in GROQ_API_KEY, JWT_SECRET, DEMO_PASSWORD
```

**Windows (PowerShell)**

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env        # then fill in GROQ_API_KEY, JWT_SECRET, DEMO_PASSWORD
```

> If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use Command Prompt (`venv\Scripts\activate.bat`).

Generate a `JWT_SECRET` (use `python3` on macOS/Linux). The backend refuses to start without one:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

**PDF generation (WeasyPrint)** needs system libraries:

```bash
brew install pango cairo gdk-pixbuf libffi     # macOS
```

On Windows, install the [GTK3 runtime](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows) and restart the terminal. JSON/CSV/Markdown export works without it.

## 12. Run

Two terminals, run at the same time.

**macOS / Linux**

```bash
# Terminal 1 -- backend
source venv/bin/activate
cd src/backend
uvicorn api:app --reload --port 8000
```

```bash
# Terminal 2 -- frontend
cd src/frontend
python3 -m http.server 5500
```

**Windows (PowerShell)**

```powershell
# Terminal 1 -- backend
venv\Scripts\Activate.ps1
cd src\backend
uvicorn api:app --reload --port 8000
```

```powershell
# Terminal 2 -- frontend
cd src\frontend
python -m http.server 5500
```

Open `http://localhost:5500/upload_configuration/` in your browser. You'll be
sent to the sign-in page first.

**Demo accounts** (created at startup when `DEMO_PASSWORD` is set, all using that password): `admin@`, `senior@`, `engineer@` and `viewer@` at `alpha.demo` and `beta.demo` -- e.g. `engineer@alpha.demo`. Or create a new organization from the sign-in page.

**Tests:** `cd src/backend` then `pytest auth/ -q`

## 13. Future Scope

- **Live device polling** — pull configs directly from devices over SSH
  instead of relying on uploaded files
- **Local/on-prem LLM option** — for organizations that can't send any
  config data to a third-party API, even redacted
- **Broader parser coverage** — deeper support for the 7 experimental
  vendors
- **Tighter CORS and a relative API base** — currently permissive/
  hardcoded for local development

## Important

Do not commit `.env`, API keys, or any other credentials. `.env` is
already excluded via `.gitignore`; if a key is ever accidentally
committed, revoke and rotate it immediately.
