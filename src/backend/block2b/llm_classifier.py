import os
import re
import json
import time
from dotenv import load_dotenv
from groq import Groq

from .memory import check_memory, save_confirmed, init_db
from .prefilter import classify_locally 

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

MODEL = "openai/gpt-oss-20b"  # good default Groq model, fast + capable

# ---------- Prompts ----------

# Fields must match shared/schema.py NormalizedConfig exactly.
# If you need a new field, message the team first -- this is a shared contract.
LINE_CLASSIFY_SYSTEM_PROMPT = """You are a network device configuration classifier.
You will be given ONE raw configuration line from a router, switch or firewall.
Decide which single NormalizedConfig field (if any) this line SETS, and give its value.
Respond with ONLY valid JSON: no markdown, no extra text.

GENERAL RULES
- A line only counts if it TURNS a feature on/off or SETS the field itself.
  Lines that merely tune, filter, name, show, clear or reference a feature are "unclear".
- Never invent values. If unsure, answer "unclear" with low confidence.
- Ignore placeholder/redacted tokens such as <REDACTED> and <IP_ADDR>.

FIELDS AND ALLOWED VALUES (use exactly these)

ssh_enabled (bool)
  true : line enables SSH (e.g. "ip ssh version 2", "transport input ssh",
         "stelnet server enable", "set system services ssh").
  false: line disables SSH (e.g. "no ip ssh", "undo stelnet server enable",
         "delete system services ssh").
  unclear: SSH parameter/reference lines that do not toggle it, e.g. "ssh server v2",
         "ssh server netconf vrf def", "set admin-ssh-port 22", "/ip ssh",
         "ssh user X service-type stelnet", "ip ssh time-out 60", "crypto key generate rsa".

telnet_enabled (bool)
  true : line enables Telnet (e.g. "transport input telnet", "set net-access telnet on",
         "telnet server enable"). If a line enables BOTH ssh and telnet
         (e.g. "transport input ssh telnet", "protocol inbound all"), answer telnet_enabled true
         (report the riskier setting).
  false: line disables Telnet (e.g. "no telnet-server", "set net-access telnet off").
  unclear: "telnet server port 1025" and other parameter lines.

session_timeout_seconds (int)
  Line sets an idle/exec/session timeout; convert to TOTAL SECONDS.
  "exec-timeout 10 0" -> 600; "ip ssh time-out 60" -> 60;
  Check Point "set inactivity-timeout 10" (minutes) -> 600;
  SonicWall "cli idle-timeout default 5" (minutes) -> 300.

logging_enabled (bool)   [NARROW definition]
  true : line turns logging on OR configures a log destination/forwarding:
         "logging on", "logging trap informational", "logging buffered 8192",
         "logging host 10.1.1.1", "logging server 10.1.1.1", "logging 1.2.3.4",
         "set system syslog host ... any notice", "add syslog log-remote-address ...",
         "info-center enable", "info-center loghost ...",
         PAN-OS "set shared log-settings ... send-syslog ...".
  false: line turns logging off: "no logging on", "no logging trap",
         "delete system syslog", "undo info-center enable".
  unclear: logging TUNING or reference lines that do not turn it on/off or set a destination:
         "logging level bgp 4", "logging rate-limit 100", "logging device-id hostname",
         "logging source-interface X", "logging facility local0", "logging suppress rule X",
         "no logging console", "no logging event ...", "show logging", "clear logging ...",
         "config log syslogd2 setting", "/system logging".

password_encryption (str) - ONLY these four values:
  "type7"  : reversible/weak: "service password-encryption", "password 7 X", "secret 7 X",
             Huawei "password cipher X".
  "type5"  : one-way MD5/crypt hash: "secret 5 $1$...", "password 5 X", Check Point
             "password-hash $1$...", Huawei "password irreversible-cipher X".
  "sha512" : "secret sha512 $6$...".
  "none"   : plaintext or no encryption: "password 0 X", "secret 0 X", "enable password X",
             "no service password-encryption", Huawei "password simple X".
  Any other scheme (secret 8, 9 or 10, sha1, scrypt, etc.) -> answer "unclear", NOT a new value.

banner_configured (bool)
  true : line sets a login/MOTD banner ("banner motd ^...^", "banner login", "set message banner on ...",
         "header login information ...").
  false: line explicitly disables/removes a banner ("set pre-login-banner disable", "no banner motd").

unclear : real config that sets none of the fields above (routing, ACLs, interfaces, hostname, SNMP,
          NTP, AAA, users, timezone, comments, empty text).

OUTPUT FORMAT (JSON only):
{"field": "<ssh_enabled|telnet_enabled|session_timeout_seconds|logging_enabled|password_encryption|banner_configured|unclear>",
 "value": <true|false|integer|"type7"|"type5"|"sha512"|"none"|null>,
 "confidence": <0.0-1.0>,
 "reasoning": "<one short sentence>"}

EXAMPLES
Line: "transport input ssh" -> {"field": "ssh_enabled", "value": true, "confidence": 0.95, "reasoning": "VTY restricted to SSH"}
Line: "transport input ssh telnet" -> {"field": "telnet_enabled", "value": true, "confidence": 0.9, "reasoning": "Telnet allowed alongside SSH (riskier)"}
Line: "ssh server v2" -> {"field": "unclear", "value": null, "confidence": 0.85, "reasoning": "SSH version parameter, not an enable/disable"}
Line: "exec-timeout 10 0" -> {"field": "session_timeout_seconds", "value": 600, "confidence": 0.95, "reasoning": "10 minutes = 600 seconds"}
Line: "logging host 198.51.100.200" -> {"field": "logging_enabled", "value": true, "confidence": 0.9, "reasoning": "Configures a syslog destination"}
Line: "logging level bgp 4" -> {"field": "logging_enabled", "value": true, "confidence": 0.85, "reasoning": "Per-facility severity tuning, not on/off"}
Line: "no logging on" -> {"field": "logging_enabled", "value": false, "confidence": 0.95, "reasoning": "Disables all logging"}
Line: "username admin privilege 15 secret 5 $1$abc$xyz" -> {"field": "password_encryption", "value": "type5", "confidence": 0.95, "reasoning": "Type 5 (MD5) hash"}
Line: "neighbor X password 7 XOF6i6" -> {"field": "password_encryption", "value": "type7", "confidence": 0.9, "reasoning": "Type 7 reversible encryption"}
Line: "username cisco privilege 15 password 0 cisco" -> {"field": "password_encryption", "value": "none", "confidence": 0.95, "reasoning": "Plaintext password"}
Line: "username netadmin secret 9 $9$abc" -> {"field": "unclear", "value": null, "confidence": 0.8, "reasoning": "Type 9 hash is not one of the allowed schemes"}
Line: "set pre-login-banner disable" -> {"field": "banner_configured", "value": false, "confidence": 0.85, "reasoning": "Banner explicitly disabled"}
Line: "router ospf 1" -> {"field": "unclear", "value": null, "confidence": 0.9, "reasoning": "Routing, not a tracked field"}
"""

VENDOR_GUESS_SYSTEM_PROMPT = """You are a network configuration vendor identifier.
Given a snippet of raw configuration text, guess which vendor/OS produced it.

Common vendors: Cisco IOS, Cisco NX-OS, Juniper JunOS, Palo Alto PAN-OS,
Fortinet FortiOS, Arista EOS, Huawei VRP, Check Point Gaia, SonicWall SonicOS, Unknown.

Distinguishing syntax markers:
- Palo Alto PAN-OS: flat "set deviceconfig ...", "set network ...", "set rulebase ...", "set zone ...", "set shared ..." (deep hierarchical paths; short "set hostname/ntp/interface" lines alone are NOT enough to pick PAN-OS)
- Juniper JunOS: "set system ...", "set interfaces ..." (plural), "set protocols ...", or curly-brace hierarchy with "system {" and "interfaces {"
- Check Point Gaia: short clish lines such as "set interface eth0 ipv4-address X mask-length N" (singular "interface"), "set static-route X nexthop gateway address Y on", "set user admin password-hash ...", "set expert-password-hash ...", "set net-access telnet on", "set inactivity-timeout N", "set message banner on ...", "add syslog log-remote-address ...", "set ntp server primary ...", "set clienv ..."
- SonicWall SonicOS: "configure" to enter config mode, "cli idle-timeout ...", "cli banner", "show current-config", "no <command>" negations, and mode-based contexts
- Fortinet FortiOS: "config system global" / "config firewall policy" blocks with "edit", "set", "next", "end"
- Cisco IOS: "hostname X", "interface GigabitEthernet", "line vty 0 4", "service password-encryption", lines separated by "!"
- Cisco NX-OS: "feature ...", "vdc ...", "interface Ethernet1/1"
- Arista EOS: like Cisco IOS but with "management api", "daemon", "interface Management1"
- Huawei VRP: "sysname X", "user-interface vty 0 4", "info-center ...", "undo ..." commands, "return" at the end

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
    cleaned = re.sub(r"```json|```", "", raw_text or "").strip()
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

ALLOWED = {
    "ssh_enabled": bool,
    "telnet_enabled": bool,
    "logging_enabled": bool,
    "banner_configured": bool,
    "session_timeout_seconds": int,
    "password_encryption": str,
}
ALLOWED_PASSWORD = {"type7", "type5", "sha512", "none"}


def validate_result(result: dict) -> dict:
    """Raise ValueError (which call_with_retry retries) on an invalid field/value.
    Anything outside the vocabulary is downgraded to 'unclear' instead of trusted."""
    field = result.get("field")
    if field == "unclear":
        result["value"] = None
        return result
    t = ALLOWED.get(field)
    v = result.get("value")
    if t is None:
        raise ValueError(f"LLM returned unknown field {field!r}")
    if not isinstance(v, t) or (t is int and isinstance(v, bool)):
        raise ValueError(f"LLM returned wrong value type for {field}: {v!r}")
    if field == "password_encryption" and v not in ALLOWED_PASSWORD:
        return {**result, "field": "unclear", "value": None,
                "reasoning": f"Out-of-vocabulary password scheme {v!r}"}
    return result

def call_with_retry(func, *args, retries=2, delay=1.5, fallback: dict = None, **kwargs):
    """
    Calls func(*args, **kwargs), retrying on exception.
    fallback: the dict shape to return (with "reasoning" filled in) if all
    retries fail. Pass CLASSIFY_FALLBACK or VENDOR_FALLBACK depending on
    which function you're wrapping -- don't reuse one shape for both.
    """
    global _quota_exhausted

    if fallback is None:
        fallback = CLASSIFY_FALLBACK

    if _quota_exhausted:
        result = dict(fallback)
        result["reasoning"] = "Groq daily quota exhausted"
        return result

    for attempt in range(retries + 1):
        try:
            return func(*args, **kwargs)
        except LLMUnavailable as e:
            # Not transient -- fall back immediately instead of sleeping.
            result = dict(fallback)
            result["reasoning"] = str(e)
            return result
        except Exception as e:
            print(f"Groq attempt {attempt} failed: {type(e).__name__}: {e}")
            if "tokens per day" in str(e):
                _quota_exhausted = True
                result = dict(fallback)
                result["reasoning"] = "Groq daily quota exhausted"
                return result
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
        max_tokens=1000,
        temperature=0,
        reasoning_effort="low",
        messages=[
            {"role": "system", "content": LINE_CLASSIFY_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg}
        ]
    )
    result = _safe_parse_json(response.choices[0].message.content, CLASSIFY_FALLBACK)
    if result.get("reasoning") == "Failed to parse LLM response":
        raise ValueError("LLM returned malformed JSON")
    
    result = validate_result(result)
    result["source"] = "llm"
    result["confidence"] = min(result.get("confidence", 0.0), 0.99)
    return result

CACHE_FILE = "block2b/llm_cache.json"
_cache = json.load(open(CACHE_FILE)) if os.path.exists(CACHE_FILE) else {}
_quota_exhausted = False

def classify_unknown_line(raw_line: str, vendor_hint: str = None) -> dict:
    if not raw_line or not raw_line.strip():
        return {"field": "unclear", "value": None, "confidence": 1.0,
                "reasoning": "Empty line", "source": "local_rules"}
    cached = check_memory(raw_line, vendor_hint)
    if cached is not None:
        return cached
    local_result = classify_locally(raw_line)    
    if local_result is not None:
        return local_result

    key = f"{vendor_hint}|{raw_line}"
    if key in _cache:
        return _cache[key]

    result = call_with_retry(
        _classify_unknown_line_inner, raw_line, vendor_hint,
        fallback=CLASSIFY_FALLBACK
    )
    # only cache real answers, never the fallback from a failed call
    if result.get("confidence", 0) > 0:
        _cache[key] = result
        with open(CACHE_FILE, "w") as f:
            json.dump(_cache, f)
    return result


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
        max_tokens=1000,
        temperature=0,
        reasoning_effort="low",
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
    # Also keep scheme words (Huawei "irreversible-cipher"/"cipher", Arista
    # "sha512") so the hash that FOLLOWS them is redacted, not the scheme word.
    redacted = re.sub(
        r'\b((?:enable\s+)?(?:secret|password))\s+'
        r'((?:\d+|cipher|irreversible-cipher|simple|sha512|sha256|scrypt|md5)\s+)?(\S+)',
        lambda m: f"{m.group(1)} {m.group(2) or ''}<REDACTED>",
        redacted, flags=re.IGNORECASE
    )

    # SNMP community strings, both common forms:
    #   snmp-server community <string> RO
    #   snmp-server host <ip> version 2c <string>
    redacted = re.sub(r'(snmp-server community\s+)(\S+)', r'\1<REDACTED>', redacted, flags=re.IGNORECASE)
    redacted = re.sub(r'(version\s+\d+c\s+)(\S+)', r'\1<REDACTED>', redacted, flags=re.IGNORECASE)

    return redacted