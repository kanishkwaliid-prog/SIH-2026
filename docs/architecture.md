# Architecture — AI-Driven Multi-Vendor Network Security Compliance Auditor

## Pipeline overview

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

## Component breakdown

**Frontend** (`src/frontend/`) — static HTML/CSS/JS, calls the backend
directly via `fetch`. No mock data; every screen reflects real API state.

**Vendor detection + parsers** (`converter/`) — signature-based detection
first; hardcoded parsers exist for Cisco, Juniper, and Palo Alto. Anything
unrecognized escalates to the LLM fallback rather than failing.

**LLM fallback + review** (`block2b/`) — a Groq-hosted model classifies
unrecognized lines after redacting sensitive values (IPs, passwords,
community strings). No LLM output is trusted automatically: it enters a
staged review queue, and only reaches permanent memory once multiple
independent reviewers (weighted by role) agree. Every promotion is
appended to a hash-chained audit log, so the training history can't be
silently altered by one person.

**Compliance engine** (`compliance_engine/`) — evaluates the resolved,
vendor-neutral config against one or more YAML rule packs (CIS, NIST,
STIG, RBI, SEBI), producing pass/fail findings with severity.

**Report generator** (`report_generator/`) — renders findings into a PDF
with a Simple View (plain-English) and Technical View (field-level detail
+ exact CLI remediation per vendor).

## Data flow guarantee

`config` (Block 2a's certain output) and `pending_confirmations` (LLM
guesses) are always kept separate until a human confirms them — nothing
LLM-guessed reaches the compliance engine unverified.