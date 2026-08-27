# AI-Powered Vendor-Agnostic Network Compliance Engine

SIH 2026 project — an AI-augmented tool that checks network device
configurations (firewalls, routers, switches) from any vendor against
security frameworks like CIS, NIST, and DISA STIGs, and generates a
report with pass/fail findings and step-by-step remediation.

## Team

| Name | Block | Responsibility |
|---|---|---|
| TBD | Block 1 | Frontend (upload, confirmation UI, report viewer) |
| TBD | Block 2a | Vendor detection + hardcoded parsers |
| TBD | Block 2b | LLM fallback + prompt engineering |
| TBD | Block 2c | Knowledge base + training/confirmation flow |
| TBD | Block 3 | Compliance engine + rule pack authoring |
| TBD | Block 4 | Report generator (PDF) |

## How the pipeline works

1. **Frontend** — user uploads a config file, optionally names the vendor
2. **Converter** — detects the vendor, converts the config into a standard
   JSON schema (see `shared/schema.py`). Falls back to an LLM guess, then
   to a human confirmation, for anything it doesn't recognize.
3. **Compliance engine** — checks the JSON against a rule pack
   (`rule_packs/`) for the chosen framework (CIS/NIST/STIG)
4. **Report generator** — turns the findings into a PDF with plain-English
   explanations, technical details, and vendor-specific CLI remediation

## Repo structure

```
frontend/            Block 1
converter/            Block 2 (detection, parsers, LLM fallback, knowledge base)
compliance_engine/    Block 3
report_generator/     Block 4
rule_packs/            CIS/NIST/STIG rules as YAML
shared/                Agreed JSON schema + sample data everyone builds against
docs/                   Architecture doc, demo video link, presentation
```

## Getting started (local setup)

```bash
git clone <repo-url>
cd <repo-name>
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env          # then fill in your LLM API key
```

## Branching workflow

- Never push directly to `main`
- Create a branch per block: `git checkout -b block2-converter`
- Commit and push regularly, not just once at the end
- Open a Pull Request into `main` when a block works; get one teammate
  to review before merging
- If you need to change `shared/schema.py`, message the team first —
  every block depends on it

## Environment variables

Copy `.env.example` to `.env` and fill in:

```
ANTHROPIC_API_KEY=your_key_here
```

Never commit `.env` — it's already in `.gitignore`.

## Deliverables checklist

- [ ] Source code (this repo)
- [ ] README with setup instructions (this file)
- [ ] Architecture document (max 2 pages) — `docs/architecture.pdf`
- [ ] Demo video (max 2 minutes) — link in `docs/demo_video.md`
- [ ] Technical presentation (max 5 slides) — `docs/presentation.pptx`
