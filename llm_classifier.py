import os
import re
import json
import time
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
client = Groq(api_key=os.getenv("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"))

MODEL = "openai/gpt-oss-120b"   # good default Groq model, fast + capable

# ---------- Prompts ----------

LINE_CLASSIFY_SYSTEM_PROMPT = """You are a network device configuration classifier.
You will be given a single raw configuration line from a network device (router, switch, or firewall).
Classify it into exactly one category and respond with ONLY valid JSON, no markdown, no extra text.

Valid categories and what they mean:
- authentication: logins, passwords, user accounts, AAA, RADIUS/TACACS
- logging: syslog, logging levels, audit trails
- encryption: SSH keys, TLS/SSL, crypto commands, hashing
- access_control: ACLs, firewall rules, permit/deny statements
- session_management: timeouts, VTY lines, session limits
- routing: static/dynamic routing, OSPF, BGP, interfaces
- other: comments, banners, hostnames, SNMP, NTP, anything that doesn't clearly fit above

Examples:
Line: "aaa new-model" → {"category": "authentication", "confidence": 0.95, "reasoning": "Enables AAA authentication framework"}
Line: "logging trap informational" → {"category": "logging", "confidence": 0.97, "reasoning": "Sets syslog trap level"}
Line: "crypto key generate rsa" → {"category": "encryption", "confidence": 0.96, "reasoning": "Generates RSA key for SSH"}
Line: "access-list 101 permit tcp any any eq 22" → {"category": "access_control", "confidence": 0.94, "reasoning": "Defines ACL rule"}
Line: "exec-timeout 10 0" → {"category": "session_management", "confidence": 0.93, "reasoning": "Sets VTY session timeout"}

Output format (JSON only):
{"category": "<one of the categories above>", "confidence": <float 0.0-1.0>, "reasoning": "<one short sentence>"}
"""

VENDOR_GUESS_SYSTEM_PROMPT = """You are a network configuration vendor identifier.
Given a snippet of raw configuration text, guess which vendor/OS produced it.

Common vendors: Cisco IOS, Cisco NX-OS, Juniper JunOS, Palo Alto PAN-OS,
Fortinet FortiOS, Arista EOS, Unknown.

Respond with ONLY valid JSON, no markdown, no extra text:
{"vendor": "<vendor name or 'Unknown'>", "confidence": <float 0.0-1.0>, "reasoning": "<one short sentence>"}
"""

# ---------- Helpers ----------

def _safe_parse_json(raw_text: str) -> dict:
    cleaned = re.sub(r"```json|```", "", raw_text).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {
            "category": "unclassified",
            "confidence": 0.0,
            "reasoning": "Failed to parse LLM response",
            "raw_response": raw_text
        }

def needs_human_review(result: dict, threshold: float = 0.6) -> bool:
    return result.get("confidence", 0.0) < threshold

def call_with_retry(func, *args, retries=2, delay=1.5, **kwargs):
    for attempt in range(retries + 1):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if attempt == retries:
                return {"category": "unclassified", "confidence": 0.0,
                         "reasoning": f"API error after retries: {str(e)}"}
            time.sleep(delay)

# ---------- Main functions ----------

def classify_unknown_line(raw_line: str, vendor_hint: str = None) -> dict:
    user_msg = f"Config line: {raw_line}"
    if vendor_hint:
        user_msg += f"\nVendor hint: {vendor_hint}"

    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=200,
        messages=[
            {"role": "system", "content": LINE_CLASSIFY_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg}
        ]
    )
    return _safe_parse_json(response.choices[0].message.content)

def guess_vendor(config_text: str) -> dict:
    snippet = "\n".join(config_text.splitlines()[:40])

    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=200,
        temperature = 0,
        messages=[
            {"role": "system", "content": VENDOR_GUESS_SYSTEM_PROMPT},
            {"role": "user", "content": snippet}
        ]
    )
    return _safe_parse_json(response.choices[0].message.content)