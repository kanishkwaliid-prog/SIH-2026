# LLM Fallback Module 

## What this does

When a config file has a line that nobody wrote a rule for (a new vendor, a
weird OS, unusual syntax), instead of the program crashing or just skipping
it, this module sends that line to an AI (via Groq) and asks it to guess
what the line means. This is the "AI-powered" part of the project.

It does two things:
1. **Reads one confusing config line and guesses its category** — is it
   about authentication, logging, encryption, access control, session
   settings, routing and other features.
2. **Reads a whole config file and guesses which vendor made it** (Cisco,
   Juniper, Palo Alto, etc.) when nobody can tell just by looking at it.

Every answer also comes with a confidence score (how sure the AI is), so if
it's not very sure, the answer can be flagged for a human to double-check
instead of being trusted blindly.

## Files

- `llm_classifier.py` — all core logic (prompts, API calls, JSON parsing,
  retry handling, confidence check).
- `test_classifier.py` — a small hand-labeled test set to sanity-check the
  classifier's accuracy.
- `.env` — holds `GROQ_API_KEY` (not committed to git).
- `.gitignore` — excludes `.env`, `venv/`, `__pycache__/` from git.

## Tech stack

- Python 3.10+
- Groq API (`groq` SDK) — model: `openai/gpt-oss-120b`
- `python-dotenv` for API key management
- Plain `json`/`re` for parsing model output — no ML training, no GPU needed

## Setup

```bash
python -m venv venv
venv\Scripts\activate          
pip install groq python-dotenv
```

Add your key to `.env`:
```
GROQ_API_KEY=your_key_here
```

Run the test suite:
```bash
python test_classifier.py
```

## The functions I built

### `classify_unknown_line(raw_line, vendor_hint=None)`
Give it one raw config line (and optionally which vendor it's from, if
known). It returns something like:
```json
{"category": "authentication", "confidence": 0.92, "reasoning": "..."}
```

### `guess_vendor(config_text)`
Give it a whole config file's text. It returns something like:
```json
{"vendor": "Cisco IOS", "confidence": 0.88, "reasoning": "..."}
```

### `needs_human_review(result, threshold=0.6)`
Checks the confidence score in a result and returns `True`/`False` — tells
you whether this particular answer is unsure enough that a human should
look at it instead of trusting it automatically.

### `call_with_retry(func, *args, retries=2, delay=1.5, **kwargs)`
A safety wrapper. If the AI call fails (bad internet, API down, rate
limit), it tries again a couple of times before giving up. If it still
fails, it returns a safe "unclassified" result instead of crashing the
whole program.

### `_safe_parse_json(raw_text)`
Cleans up the AI's raw reply (sometimes it adds markdown formatting around
the JSON) and safely converts it into a usable Python dictionary. If the
AI's reply is broken or unreadable, this also returns a safe fallback
instead of crashing.

## Testing done so far

**1. Accuracy test** — ran 8+ hand-picked config lines with known correct
answers through `classify_unknown_line()`. Result: 7/8 correct on the first
run. The vendor guess function was also tested on a sample config and
correctly identified it as Palo Alto PAN-OS with 97% confidence.

**2. Failure test** — deliberately used a broken/invalid API key to check
that the program doesn't crash when the AI service fails. Result: it
correctly caught the error, retried, and returned a safe fallback answer
instead of crashing.

**3. Edge case test** — tested weird/messy inputs: an empty line, a
whitespace-only line, random gibberish symbols, a very long meaningless
line, and a comment line. Result: all 5 were safely classified as "other"
with high confidence, meaning the AI correctly recognized none of them were
real config content, instead of confidently guessing something wrong.

## Current status

Core work is complete and tested:
- Both main functions work correctly
- Confidence scoring works, so low-confidence answers can be flagged
- The program survives API failures without crashing
- Handles messy/garbage input safely

