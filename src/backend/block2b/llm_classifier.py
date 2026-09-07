import os
import re
import json
import time
from dotenv import load_dotenv
from groq import Groq

from .memory import check_memory, save_confirmed, init_db

load_dotenv()

# The client is built lazily instead of at import time. Constructing Groq()
# with no GROQ_API_KEY raises immediately, which used to make *importing* this
# module fail -- and since pipeline.py imports it, that took down the whole
# app (and every test) for anyone without a key in their .env.
#
# Deferring it means the app boots fine without a key; the failure surfaces
# per-call inside call_with_retry, which already handles it by returning the
# proper fallback shape. That is the Tier 3 path pipeline.py documents: lines
# come back as "unclear" for a human to resolve on the review screen.
_client = None


class LLMUnavailable(RuntimeError):
    """The LLM cannot be reached at all (e.g. no API key configured).

    Kept distinct from transient API errors so call_with_retry doesn't burn
    retries + sleeps on a condition that cannot possibly resolve mid-run.
    Without this, analysing a config with N unknown lines and no key took
    N * retries * delay seconds of pointless waiting before falling back.
    """


def get_client():
    global _client
    if _client is None:
        if not os.getenv("GROQ_API_KEY"):
            raise LLMUnavailable(
                "GROQ_API_KEY is not set -- LLM classification is disabled, "
                "so this line is being sent straight to human review."
            )
        _client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    return _client


init_db()  # safe to call every import -- CREATE TABLE IF NOT EXISTS

MODEL = "openai/gpt-oss-120b"   # good default Groq model, fast + capable

# ---------- Prompts ----------

# Fields must match shared/schema.py NormalizedConfig exactly.
# If you need a new field, message the team first -- this is a shared contract.
LINE_CLASSIFY_SYSTEM_PROMPT = """You are a network device configuration classifier.
You will be given a single raw configuration line from a network device (router, switch, or firewall).
Decide which single NormalizedConfig field (if any) this line sets, and extract its value.
Respond with ONLY valid JSON, no markdown, no extra text.

Valid fields and their value types:
- ssh_enabled (bool): line enables/disables SSH access (e.g. "ip ssh version 2", "transport input ssh")
- telnet_enabled (bool): line enables/disables Telnet access (e.g. "transport input telnet")
- session_timeout_seconds (int): line sets a session/exec timeout, converted to total seconds
  (e.g. "exec-timeout 10 0" means 10 minutes 0 seconds -> 600)
- logging_enabled (bool): line turns logging/syslog on or off (e.g. "logging trap informational" -> true,
  "no logging on" -> false)
- password_encryption (str): line sets a password encryption/hashing scheme -- use the short form
  the device uses, e.g. "type7", "md5", "none", "type5"
- banner_configured (bool): line sets a login/MOTD banner (e.g. "banner motd ^...")
- unclear: the line is real config but doesn't clearly set any of the fields above
  (e.g. routing, ACLs, interfaces, hostname, SNMP, NTP, comments)

Output format (JSON only):
{"field": "<one of: ssh_enabled|telnet_enabled|session_timeout_seconds|logging_enabled|password_encryption|banner_configured|unclear>",
 "value": <bool, int, string, or null if field is "unclear">,
 "confidence": <float 0.0-1.0>,
 "reasoning": "<one short sentence>"}

Examples:
Line: "transport input ssh" -> {"field": "ssh_enabled", "value": true, "confidence": 0.95, "reasoning": "Restricts VTY transport to SSH only"}
Line: "transport input telnet ssh" -> {"field": "telnet_enabled", "value": true, "confidence": 0.9, "reasoning": "Telnet is allowed alongside SSH"}
Line: "exec-timeout 10 0" -> {"field": "session_timeout_seconds", "value": 600, "confidence": 0.95, "reasoning": "10 minutes converted to seconds"}
Line: "logging trap informational" -> {"field": "logging_enabled", "value": true, "confidence": 0.9, "reasoning": "Enables syslog trap output"}
Line: "service password-encryption" -> {"field": "password_encryption", "value": "type7", "confidence": 0.9, "reasoning": "Enables Cisco type7 weak encryption"}
Line: "banner motd ^Authorized access only^" -> {"field": "banner_configured", "value": true, "confidence": 0.95, "reasoning": "Sets a login banner"}
Line: "router ospf 1" -> {"field": "unclear", "value": null, "confidence": 0.9, "reasoning": "Routing config, not in NormalizedConfig"}
"""

VENDOR_GUESS_SYSTEM_PROMPT = """You are a network configuration vendor identifier.
Given a snippet of raw configuration text, guess which vendor/OS produced it.

Common vendors: Cisco IOS, Cisco NX-OS, Juniper JunOS, Palo Alto PAN-OS,
Fortinet FortiOS, Arista EOS, Unknown.

Respond with ONLY valid JSON, no markdown, no extra text:
{"vendor": "<vendor name or 'Unknown'>", "confidence": <float 0.0-1.0>, "reasoning": "<one short sentence>"}
"""

# ---------- Fallback shapes ----------
# call_with_retry needs to know which shape to fall back to, since
# classify_unknown_line and guess_vendor return different keys.

CLASSIFY_FALLBACK = {
    "field": "unclear",
    "value": None,
    "confidence": 0.0,
    "reasoning": None,  # filled in with the error message at call time
    "source": "llm_fallback",
}

VENDOR_FALLBACK = {
    "vendor": "Unknown",
    "confidence": 0.0,
    "reasoning": None,
    "source": "llm_fallback",
}

# ---------- Helpers ----------

def _safe_parse_json(raw_text: str, fallback: dict) -> dict:
    """
    fallback: the dict shape to return if the LLM's response isn't valid
    JSON. Pass CLASSIFY_FALLBACK or VENDOR_FALLBACK depending on which
    function is calling this -- they have different keys (field/value vs
    vendor), so a single hardcoded fallback shape here would silently
    return the wrong shape to whichever caller didn't match it.
    """
    cleaned = re.sub(r"```json|```", "", raw_text).strip()
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    cleaned = match.group(0) if match else cleaned
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        result = dict(fallback)
        result["reasoning"] = "Failed to parse LLM response"
        result["raw_response"] = raw_text
        return result

def needs_human_review(result: dict, threshold: float = 0.6) -> bool:
    return result.get("confidence", 0.0) < threshold

def call_with_retry(func, *args, retries=2, delay=1.5, fallback: dict = None, **kwargs):
    """
    Calls func(*args, **kwargs), retrying on exception.
    fallback: the dict shape to return (with "reasoning" filled in) if all
    retries fail. Pass CLASSIFY_FALLBACK or VENDOR_FALLBACK depending on
    which function you're wrapping -- don't reuse one shape for both.
    """
    if fallback is None:
        fallback = CLASSIFY_FALLBACK

    for attempt in range(retries + 1):
        try:
            return func(*args, **kwargs)
        except LLMUnavailable as e:
            # Not transient -- fall back immediately instead of sleeping.
            result = dict(fallback)
            result["reasoning"] = str(e)
            return result
        except Exception as e:
            if attempt == retries:
                result = dict(fallback)
                result["reasoning"] = f"API error after retries: {str(e)}"
                return result
            time.sleep(delay)

# ---------- Main functions ----------

def _classify_unknown_line_inner(raw_line: str, vendor_hint: str = None) -> dict:
    redacted_line = redact_sensitive(raw_line)
    user_msg = f"Config line: {redacted_line}"
    if vendor_hint:
        user_msg += f"\nVendor hint: {vendor_hint}"

    response = get_client().chat.completions.create(
        model=MODEL,
        max_tokens=200,
        messages=[
            {"role": "system", "content": LINE_CLASSIFY_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg}
        ]
    )
    result = _safe_parse_json(response.choices[0].message.content, CLASSIFY_FALLBACK)
    if result.get("reasoning") == "Failed to parse LLM response":
        raise ValueError("LLM returned malformed JSON")
    result["source"] = "llm"
    result["confidence"] = min(result.get("confidence", 0.0), 0.99)
    return result

def classify_unknown_line(raw_line: str, vendor_hint: str = None) -> dict:
    cached = check_memory(raw_line, vendor_hint)
    if cached is not None:
        return cached

    return call_with_retry(
        _classify_unknown_line_inner, raw_line, vendor_hint,
        fallback=CLASSIFY_FALLBACK
    )


def confirm_classification(raw_line: str, field: str, value, vendor_hint: str = None,
                            confirmed_by: str = None):
    """
    Call this from the review-unknown-lines screen once a human confirms
    (or corrects) a classification. Saves it to memory so this exact line
    is never sent to the LLM again.
    """
    save_confirmed(raw_line, field, value, vendor_hint=vendor_hint, confirmed_by=confirmed_by)

def _guess_vendor_inner(config_text: str) -> dict:
    snippet = "\n".join(config_text.splitlines()[:40])
    snippet = redact_sensitive(snippet)

    response = get_client().chat.completions.create(
        model=MODEL,
        max_tokens=400,
        temperature=0,
        messages=[
            {"role": "system", "content": VENDOR_GUESS_SYSTEM_PROMPT},
            {"role": "user", "content": snippet}
        ]
    )
    result = _safe_parse_json(response.choices[0].message.content, VENDOR_FALLBACK)
    if result.get("reasoning") == "Failed to parse LLM response":
        raise ValueError("LLM returned malformed JSON")
    result["source"] = "llm"
    result["confidence"] = min(result.get("confidence", 0.0), 0.99)
    return result

def guess_vendor(config_text: str) -> dict:
    return call_with_retry(
        _guess_vendor_inner, config_text,
        fallback=VENDOR_FALLBACK
    )

def redact_sensitive(text: str) -> str:
    """
    Strips values that reveal real network topology or credentials before
    this text is sent to the cloud LLM. The classifier only needs to
    recognize COMMAND STRUCTURE (is this SSH-related? what encryption
    scheme?) -- it never needs to see the actual IP, password, or
    community string. Check LINE_CLASSIFY_SYSTEM_PROMPT above: the
    "value" the model returns is always a bool/int/scheme-name
    (true, 600, "type7"), never a raw secret -- so redacting the secret
    itself costs no classification accuracy.

    This is a heuristic covering the common cases, not an exhaustive
    DLP filter -- flag any pattern that slips through so it can be added.
    """
    redacted = text

    # IPv4 addresses (also catches subnet masks -- harmless to redact those too)
    redacted = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b', '<IP_ADDR>', redacted)

    # Cisco-style secrets: "password X", "secret X", "enable secret 5 X",
    # "username admin secret 5 X" -- keep the keyword + type-number prefix
    # (needed to tell type5 vs type7 apart), redact only the actual value.
    redacted = re.sub(
        r'\b((?:enable\s+)?(?:secret|password))\s+(\d+\s+)?(\S+)',
        lambda m: f"{m.group(1)} {m.group(2) or ''}<REDACTED>",
        redacted, flags=re.IGNORECASE
    )

    # SNMP community strings, both common forms:
    #   snmp-server community <string> RO
    #   snmp-server host <ip> version 2c <string>
    redacted = re.sub(r'(snmp-server community\s+)(\S+)', r'\1<REDACTED>', redacted, flags=re.IGNORECASE)
    redacted = re.sub(r'(version\s+\d+c\s+)(\S+)', r'\1<REDACTED>', redacted, flags=re.IGNORECASE)

    return redacted