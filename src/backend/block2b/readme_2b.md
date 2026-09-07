# LLM Fallback Module

## What this does

When a config file has a line that nobody wrote a rule for (a new vendor, a
weird OS, unusual syntax), instead of the program crashing or just skipping
it, this module sends that line to an AI (via Groq) and asks it to figure
out what setting it maps to. This is the "AI-powered" part of the project.

It does three things:
1. **Reads one confusing config line and maps it to a NormalizedConfig
   field** (from `shared/schema.py`) — e.g. does this line enable SSH,
   disable Telnet, set a session timeout, etc. — and extracts the value.
   Lines that don't map to any tracked field are marked `unclear`.
2. **Reads a whole config file and guesses which vendor made it** (Cisco,
   Juniper, Palo Alto, etc.) when nobody can tell just by looking at it.
3. **Remembers confirmed answers** in a local SQLite database, so once a
   human confirms what a line means, that exact line is never sent to the
   AI again.

Every AI answer also comes with a confidence score (how sure the AI is), so
if it's not very sure, the answer can be flagged for a human to
double-check instead of being trusted blindly.

## Files

All paths below are relative to `src/backend/` (this module's parent
directory once the project moved to the `src/frontend` + `src/backend`
layout):

- `block2b/llm_classifier.py` — all core logic (prompts, API calls, JSON
  parsing, retry handling, confidence check, memory lookup).
- `block2b/memory.py` — SQLite-backed cache of human-confirmed
  classifications.
- `block2b/test_classifier.py` — a hand-labeled test set to sanity-check
  the classifier's accuracy against the shared schema fields.
- `.env` — holds `GROQ_API_KEY`, lives at the **repo root**, not inside
  `block2b/` (not committed to git).
- `.gitignore` — also at the repo root; excludes `.env`, `venv/`,
  `__pycache__/`, `memory.db` from git for the whole project.

## Tech stack

- Python 3.10+
- Groq API (`groq` SDK) — model: `openai/gpt-oss-120b`
- `python-dotenv` for API key management
- `sqlite3` (built into Python) for the memory cache
- Plain `json`/`re` for parsing model output — no ML training, no GPU needed

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

## The functions I built

### `classify_unknown_line(raw_line, vendor_hint=None)`
Give it one raw config line (and optionally which vendor it's from, if
known). It checks memory first for an exact match; if not found, it calls
the LLM. Returns something like:
```json
{"field": "ssh_enabled", "value": true, "confidence": 0.95, "reasoning": "..."}
```
`field` is always one of the `NormalizedConfig` field names from
`shared/schema.py` (`ssh_enabled`, `telnet_enabled`,
`session_timeout_seconds`, `logging_enabled`, `password_encryption`,
`banner_configured`), or `"unclear"` if the line doesn't map to a tracked
field.

### `confirm_classification(raw_line, field, value, vendor_hint=None, confirmed_by=None)`
Call this once a human confirms (or corrects) a classification, e.g. from
a "review unknown lines" screen. Saves the line + answer to memory so it's
never sent to the LLM again.

### `guess_vendor(config_text)`
Give it a whole config file's text. It returns something like:
```json
{"vendor": "Cisco IOS", "confidence": 0.88, "reasoning": "..."}
```

### `needs_human_review(result, threshold=0.6)`
Checks the confidence score in a result and returns `True`/`False` — tells
you whether this particular answer is unsure enough that a human should
look at it instead of trusting it automatically.

### `call_with_retry(func, *args, retries=2, delay=1.5, fallback=None, **kwargs)`
A safety wrapper. If the AI call fails (bad internet, API down, rate
limit), it tries again a couple of times before giving up. If it still
fails, it returns a safe fallback result instead of crashing the whole
program. `classify_unknown_line` and `guess_vendor` each pass their own
fallback shape, since they return different keys (`field`/`value` vs
`vendor`).

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

## Memory (`memory.py`)

- `check_memory(raw_line, vendor_hint=None)` — returns a cached result if
  this exact line (whitespace/case-normalized) was confirmed before, else
  `None`.
- `save_confirmed(raw_line, field, value, ...)` — writes a confirmed
  mapping to `memory.db`.
- `init_db()` — creates the table if it doesn't exist yet; called
  automatically on import.

Memory is keyed on the normalized line text only, not vendor — the
assumption is that a line like `transport input ssh` means the same thing
regardless of vendor. If that assumption breaks for some field, that's a
team discussion before changing the cache key.

## Testing done so far

**1. Accuracy test** — 17 hand-picked config lines with known correct
`(field, value)` answers run through `classify_unknown_line()`. Latest
run: **16/17**. The one miss (`no logging console`) is a genuinely
ambiguous line — it only disables console output, not logging overall —
and this run the LLM confidently guessed `logging_enabled: False` instead
of flagging it `unclear`. This line is expected to be borderline and is
called out in the test file itself; it isn't a sign of a broken
classifier. The vendor guess function was also tested on a sample config
and correctly identified it as Palo Alto PAN-OS with 98% confidence.

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
of confidently guessing a wrong field.

Run it yourself with `python3 block2b/test_classifier.py` (from
`src/backend/`) — see Setup above.

## Current status

Core work is complete and tested:
- Classifier output matches the shared `NormalizedConfig` schema
  (`field`/`value` pairs, not free-text categories)
- Confidence scoring works, so low-confidence answers can be flagged
- The program survives API failures without crashing, with correct
  per-function fallback shapes
- The client is built lazily, so the app and its imports survive a
  missing `GROQ_API_KEY` entirely rather than crashing on startup
- Handles messy/garbage input safely
- Confirmed answers are cached in SQLite so repeat lines skip the LLM call