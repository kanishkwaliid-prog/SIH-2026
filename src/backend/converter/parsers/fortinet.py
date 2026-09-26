"""
Block 2a - Fortinet FortiOS parser.

Handles the standard FortiOS CLI export style:
    config system global
        set admintimeout 30
    end

A check is only filled in when its exact line is found (or when the
config clearly has a system section but no matching line). Anything
else stays None, i.e. "Not Evaluated".
"""

import re

# Top-level sections we understand. Lines inside these are not sent to
# Block 2b as "unrecognized" even when we don't extract a field from them.
KNOWN_SECTIONS = (
    "system global", "system interface", "system admin", "system snmp",
    "system dns", "system ntp", "system settings", "system ha",
    "system zone", "system session-ttl", "log ", "router static",
    "firewall address", "firewall addrgrp", "firewall service",
    "firewall policy", "firewall vip", "firewall ippool",
)
STRUCTURAL_SECTIONS = ("vdom", "global")
KNOWN_WEAK_COMMUNITIES = {"public", "private", "cisco", "community"}


def _blocks(config_text: str, header_regex: str) -> list[str]:
    """Text inside every 'config <header>' ... 'end' block."""
    return re.findall(
        rf"^config {header_regex}[ \t]*\n(.*?)^end",
        config_text,
        re.MULTILINE | re.DOTALL,
    )


def parse_fortinet(config_text: str) -> tuple[dict, list[str]]:
    """Returns (fields, unrecognized_lines)."""
    fields = {
        "ssh_enabled": None,
        "telnet_enabled": None,
        "session_timeout_seconds": None,
        "logging_enabled": None,
        "password_encryption": None,
        "banner_configured": None,
        "snmp_default_community": None,
    }

    has_system = bool(
        re.search(r"^config system (global|interface)", config_text, re.MULTILINE)
    )

    # --- Telnet / SSH: which services each interface allows ---
    access_lines = re.findall(r"^\s*set allowaccess (.+)$", config_text, re.MULTILINE)
    access_words = " ".join(access_lines).split()

    if (
        re.search(r"^\s*set admin-telnet enable", config_text, re.MULTILINE)
        or "telnet" in access_words
    ):
        fields["telnet_enabled"] = True
    elif re.search(r"^\s*set admin-telnet disable", config_text, re.MULTILINE):
        fields["telnet_enabled"] = False

    if "ssh" in access_words:
        fields["ssh_enabled"] = True
    elif access_lines:
        fields["ssh_enabled"] = False

    # --- Idle timeout (FortiOS stores minutes) ---
    timeout_match = re.search(r"^\s*set admintimeout (\d+)", config_text, re.MULTILINE)
    if timeout_match:
        fields["session_timeout_seconds"] = int(timeout_match.group(1)) * 60

    # --- Logging: a remote syslog or FortiAnalyzer target that is enabled ---
    log_blocks = _blocks(config_text, r"log (?:syslogd\d?|fortianalyzer\d?) setting")
    if any(re.search(r"^\s*set status enable", b, re.MULTILINE) for b in log_blocks):
        fields["logging_enabled"] = True
    elif has_system:
        fields["logging_enabled"] = False

    # --- Login banner ---
    if re.search(r"^\s*set (?:pre|post)-login-banner enable", config_text, re.MULTILINE):
        fields["banner_configured"] = True
    elif has_system:
        fields["banner_configured"] = False

    # --- SNMP: keep only weak/default community names, same as Cisco ---
    names = []
    for block in _blocks(config_text, r"system snmp community"):
        names += re.findall(r'^\s*set name "?([^"\s]+)', block, re.MULTILINE)
    if names:
        fields["snmp_default_community"] = [
            c for c in names if c.lower() in KNOWN_WEAK_COMMUNITIES
        ]

    # password_encryption is left as None for now (see notes in chat).

    # --- Unrecognized lines: anything outside the sections we know ---
    unrecognized_lines = []
    stack = []
    for line in config_text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s == "next" or s.startswith("edit "):
            continue
        if s.startswith("config "):
            name = s[len("config "):]
            in_known = name in STRUCTURAL_SECTIONS or name.startswith(KNOWN_SECTIONS) or any(
                n.startswith(KNOWN_SECTIONS) for n in stack
            )
            if not in_known:
                unrecognized_lines.append(s)
            stack.append(name)
            continue
        if s == "end":
            if stack:
                stack.pop()
            continue
        if not any(n.startswith(KNOWN_SECTIONS) for n in stack):
            unrecognized_lines.append(s)

    return fields, unrecognized_lines