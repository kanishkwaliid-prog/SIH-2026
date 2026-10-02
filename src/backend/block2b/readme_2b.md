# Local Prefilter (ML Model) and LLM Fallback Module

## What this does

When a config file has a line that nobody wrote a rule for (a new vendor, a
weird OS, unusual syntax), instead of the program crashing or just skipping
it, this module works out what setting the line maps to. It tries the local options first (remembered answers, hand-written rules and a diverse trained ML model) and only sends the line to an AI (via Groq) if none of
those can answer. This is the "AI-powered" part of the project.

It does four things:
1. **Reads one confusing config line and maps it to a NormalizedConfig
   field** (from `shared/schema.py`) — e.g. does this line enable SSH,
   disable Telnet, set a session timeout, etc. — and extracts the value.
   Lines that don't map to any tracked field are marked `unclear`.
2. **Answers locally when it can.** A rules layer and a small ML model
   catch lines that are obviously one of the tracked settings, so they never
   cost an API call.
3. **Reads a whole config file and guesses which vendor made it** (Cisco,
   Juniper, Palo Alto, etc.) when nobody can tell just by looking at it.
4. **Remembers confirmed answers** in a local SQLite database, so once a
   human confirms what a line means, that exact line is never sent to the
   AI again. Memory is kept separately for each organisation.

Every answer also comes with a confidence score (how sure the model is), so
if it's not very sure, the answer can be flagged for a human to
double-check instead of being trusted blindly.

### How a line gets answered

`classify_unknown_line` works down this list and stops at the first layer
that can answer:

1. **Empty or whitespace-only line** — returned as `unclear` straight away.
2. **Memory** — a line a human already confirmed for this organisation.
3. **Local pre-filter** — hand-written regex rules first, then the ML model.
4. **In-process cache** — an earlier AI answer for the same (redacted) line.
5. **Groq AI** — the line is redacted and safety-checked, then sent.
6. **Fallback** — if everything fails, `unclear`, so a human resolves it on
   the review screen.

The `source` field in every result says which layer answered
(e.g. `local_rules`, `llm`, `llm_fallback`).

## Files

All paths below are relative to `src/backend/` (this module's parent
directory once the project moved to the `src/frontend` + `src/backend`
layout):

- `block2b/llm_classifier.py` — all core logic (prompts, API calls, JSON
  parsing, output validation, retry handling, confidence check, memory
  lookup, and the order of the layers above).
- `block2b/memory.py` — SQLite-backed cache of human-confirmed
  classifications, separate per organisation.
- `block2b/prefilter.py` — the local layer: runs the rules, then the ML
  model (`prefilter_model.joblib`).
- `block2b/rules_prefilter.py` — the hand-written regex rules that run before
  the model.
- `block2b/train_prefilter.py` and `block2b/tune_prefilter_threshold.py` —
  retrain the ML model and tune its confidence threshold.
- `block2b/prefilter_training_data.csv`, `prefilter_holdout.csv`,
  `real_eval.csv` — training and evaluation data for the ML model.
- `block2b/compare_local_vs_llm.py` — runs the local layer and Groq on the
  same lines and lists where they disagree.
- `block2b/redaction.py` — strips sensitive values from a line before it is
  sent to Groq. Tested by `test_redaction.py` and `test_redaction_extra.py`.
- `block2b/test_classifier.py` — a hand-labeled test set to sanity-check
  the classifier's accuracy against the shared schema fields.
- `.env` — holds `GROQ_API_KEY`, lives at the **repo root**, not inside
  `block2b/` (not committed to git).
- `.gitignore` — also at the repo root; excludes `.env`, `venv/`,
  `__pycache__/`, `memory.db`, `llm_cache.json` from git for the whole
  project.

## Tech stack

- Python 3.10+
- Groq API (`groq` SDK) — model: `openai/gpt-oss-20b`
- `scikit-learn` (version pinned in `requirements.txt`) and `joblib` for the
  local TF-IDF ML model — trains in seconds on a normal laptop, no GPU needed
- `python-dotenv` for API key management
- `sqlite3` (built into Python) for the memory cache
- Plain `json`/`re` for parsing model output

## Setup

From the repo root:

```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env          # then fill in your Groq API key
```

Run the test suite (from `src/backend/`, so `block2b` resolves as a
package — see `test_classifier.py`'s `sys.path` handling):

```bash
cd src/backend
python3 block2b/test_classifier.py
```

To retrain the local ML model after changing the labels or rules:

```bash
python -m block2b.train_prefilter
```

## The functions we built

### `classify_unknown_line(raw_line, vendor_hint=None, *, org_id)`
Give it one raw config line (and optionally which vendor it's from, if
known), plus the `org_id` of the organisation the line belongs to. It goes
through the layers listed above and returns something like:
```json
{"field": "ssh_enabled", "value": true, "confidence": 0.95, "reasoning": "..."}
```
`field` is always one of the `NormalizedConfig` field names from
`shared/schema.py` (`ssh_enabled`, `telnet_enabled`,
`session_timeout_seconds`, `logging_enabled`, `password_encryption`,
`banner_configured`), or `"unclear"` if the line doesn't map to a tracked
field. `org_id` is a required keyword argument so one organisation's
confirmed lines are never used for another.

### `confirm_classification(raw_line, field, value, vendor_hint=None, confirmed_by=None, *, org_id)`
Call this once a human confirms (or corrects) a classification, e.g. from
a "review unknown lines" screen. Saves the line + answer to memory so it's
never sent to the LLM again for that organisation.

### `guess_vendor(config_text)`
Give it a whole config file's text. It returns something like:
```json
{"vendor": "Cisco IOS", "confidence": 0.88, "reasoning": "..."}
```
Only the first 40 lines are used. They are redacted first, and any line that
still looks risky is dropped. If nothing safe is left, it returns `Unknown`
and the user picks the vendor manually.

### `needs_human_review(result, threshold=0.6)`
Checks the confidence score in a result and returns `True`/`False` — tells
you whether this particular answer is unsure enough that a human should
look at it instead of trusting it automatically.

### `validate_result(result)`
Checks the AI's answer before it is accepted. The field must be one of the
tracked fields and the value must be the right type (true/false for the
on/off settings, a whole number for `session_timeout_seconds`, and one of
`type7`, `type5`, `sha512`, `none` for `password_encryption`). A bad answer
is retried. A `password_encryption` value outside the allowed list is
downgraded to `unclear` instead of being trusted.

### `call_with_retry(func, *args, retries=2, delay=1.5, fallback=None, **kwargs)`
A safety wrapper. If the AI call fails (bad internet, API down, rate
limit), it tries again a couple of times before giving up. If it still
fails, it returns a safe fallback result instead of crashing the whole
program. `classify_unknown_line` and `guess_vendor` each pass their own
fallback shape, since they return different keys (`field`/`value` vs
`vendor`). Two cases skip the retries: a missing API key or a line blocked
by the safety gate (retrying can't help), and a "tokens per day" quota error
(the rest of the run falls back immediately instead of hammering the API).

### `_safe_parse_json(raw_text)`
Cleans up the AI's raw reply (sometimes it adds markdown formatting around
the JSON) and safely converts it into a usable Python dictionary. If the
AI's reply is broken or unreadable, this also returns a safe fallback
instead of crashing.

### The Groq client is built lazily (`get_client()`, not a plain `client`)
`llm_classifier.py` doesn't create the `Groq` client at import time.
Constructing it eagerly meant importing this module at all would crash
immediately for anyone without a `GROQ_API_KEY` in their `.env` — and
since `pipeline.py` imports this module, that took down the whole app (and
every test) for any teammate who hadn't set up a key yet.

Instead, `get_client()` builds the client the first time it's actually
needed and caches it in a private module-level `_client`. If no key is
set, it raises `LLMUnavailable` (a dedicated exception, kept separate from
transient API errors so `call_with_retry` doesn't waste retries + sleep
time on a condition that can't possibly resolve mid-run). The practical
effect: the app boots fine with no key at all, and any line that would've
needed the LLM instead comes back `unclear` for a human to resolve on the
review screen — this is the Tier 3 path `pipeline.py`'s docstring
describes.

## Local pre-filter (`prefilter.py`, `rules_prefilter.py`)

The pre-filter sits in front of the Groq call and catches lines that are
obviously one of the tracked settings, so they don't cost an API call.

- **Rules first.** `rules_prefilter.py` holds regex rules such as
  `no ip ssh` -> `ssh_enabled: false`. If exactly one rule matches, that
  answer is returned with confidence 1.0 and `source: "local_rules"`.
- **A line that sets two fields** (like `protocol inbound all`, which opens
  both SSH and Telnet) reports the riskier one, Telnet enabled, so an audit
  never misses an open Telnet. Other multi-match combinations go to the AI.
- **ML model second.** If no rule matches, a TF-IDF model
  (`prefilter_model.joblib`, trained with `train_prefilter.py`) predicts a
  combined label such as `ssh_enabled:true`. The answer is used only if its
  confidence is at least 0.70. Otherwise the line goes to Groq.
- **Timeouts always go to the AI.** `session_timeout_seconds` is never
  predicted locally, because turning `exec-timeout 10 0` into `600` needs
  arithmetic, not classification.
- If the model file is missing, the local layer is skipped and everything
  that isn't answered by a rule goes to Groq. Run
  `python -m block2b.train_prefilter` to create it.

## Redaction and the safety gate (`redaction.py`)

The classifier only needs the command structure ("is this an SSH command?
which password-encryption scheme?"). It never needs real IPs, hostnames,
usernames, descriptions, keys or banner text, so these are removed before a
line is sent to Groq.

- `redact_sensitive(text)` strips known categories: passwords and keys, SNMP
  communities, hostnames, usernames, domain names, email addresses, URLs,
  free text (descriptions, remarks, banners), ACL names, and IPv4, IPv6 and
  MAC addresses.
- `residual_risk(line)` is a safety gate. If a redacted line still looks
  risky, it is **not sent**; the line goes to human review instead.
- This is a pattern-based filter, not a full data-loss-prevention system. A
  sensitive value in a syntax we haven't seen can still get through. When you
  find one, add a pattern and a test. Describe the feature as "known
  sensitive categories are stripped before sending", never as "nothing
  sensitive is sent".

## Memory (`memory.py`)

- `check_memory(raw_line, vendor_hint=None, *, org_id)` — returns a cached
  result if this exact line (whitespace/case-normalized) was confirmed
  before **by this organisation**, else `None`.
- `save_confirmed(raw_line, field, value, ..., *, org_id)` — writes a
  confirmed mapping to `memory.db`.
- `init_db()` — creates the table if it doesn't exist yet; called
  automatically on import. It also upgrades an older table that had no
  `org_id` column.

Memory is keyed on the organisation and the normalized line text, not
vendor — the assumption is that a line like `transport input ssh` means the
same thing regardless of vendor. If that assumption breaks for some field,
that's a team discussion before changing the cache key.

## Labeling conventions

These decisions keep the eval labels, the local rules and the AI prompt in
agreement:

- `logging_enabled` is `true` when a line turns logging on **or** configures
  a log destination or severity level (`logging host ...`,
  `logging trap ...`, `logging level bgp 4`). It is `false` when a line turns
  logging off (`no logging on`). Lines that only tune or look at logging
  without setting a destination (`logging rate-limit 100`,
  `no logging console`, `show logging`) are `unclear`.
- `banner_configured` is `false` for lines that explicitly disable or remove
  a banner (`set pre-login-banner disable`, `no banner motd`).

## Testing done so far

**1. Accuracy test** — 30 hand-picked config lines with known correct
`(field, value)` answers run through `classify_unknown_line()`. Latest
run: **30/30**. The vendor guess function was also tested on a sample config
and correctly identified it as Palo Alto PAN-OS.

**2. Failure tests** — deliberately swapped in a client built with an
invalid API key to check that the program doesn't crash when the AI
service rejects the request. Tested separately for both
`classify_unknown_line` (falls back to `field: "unclear"`) and
`guess_vendor` (falls back to `vendor: "Unknown"`), since they use
different fallback shapes. Both correctly caught the `401 Invalid API Key`
error, retried, and returned a safe fallback instead of crashing.

**3. Edge case test** — tested weird/messy inputs: an empty line, a
whitespace-only line, random gibberish symbols, a very long meaningless
line, and a comment line. All were safely classified as `unclear` instead
of confidently guessing a wrong field. Empty and whitespace-only lines are
answered immediately (confidence 1.0) without calling the AI.

**4. Redaction tests** — `test_redaction.py` and `test_redaction_extra.py`
cover each category of sensitive value that is stripped before sending.

**5. Local ML model** — evaluated on held-out and real config lines
(`prefilter_holdout.csv`, `real_eval.csv`). As of today, before the
logging and banner label update: 99.6% precision, 114/114 real settings.
Re-measure after retraining and update this line.

Run the accuracy and failure tests yourself with
`python3 block2b/test_classifier.py` (from `src/backend/`) — see Setup above.

## Current status

Core work is complete and tested:
- Classifier output matches the shared `NormalizedConfig` schema
  (`field`/`value` pairs, not free-text categories)
- Memory, rules and a local ML model answer most lines before the AI is
  called, so they cost no API call
- Lines are redacted and safety-checked before anything is sent to Groq
- The AI's answer is validated before it is trusted
- Confidence scoring works, so low-confidence answers can be flagged
- The program survives API failures without crashing, with correct
  per-function fallback shapes
- The client is built lazily, so the app and its imports survive a
  missing `GROQ_API_KEY` entirely rather than crashing on startup
- Handles messy/garbage input safely
- Confirmed answers are cached in SQLite per organisation, so repeat lines
  skip the LLM call

Still to do:
- Set the 2 `set pre-login-banner disable` lines in the eval and training
  labels to `banner_configured: false`, retrain the local model, and rerun
  `compare_local_vs_llm.py` to confirm the logging and banner disagreements
  are gone.
- `block2b/batch_check.py` calls `classify_unknown_line` without `org_id` and
  needs updating to the current signature.