"""
Block 2a - Cisco IOS parser.

Extracts known fields from a Cisco IOS config into the shared schema.
Any line that doesn't match a known pattern is collected into
unrecognized_lines and handed off to Block 2b.
"""

import re

# Every command prefix this parser understands. Anything NOT matching
# one of these gets flagged as unrecognized -- this list should grow
# as the team encounters more real Cisco configs.
KNOWN_LINE_PATTERNS = [
    r"^version ", r"^enable$", r"^configure terminal$", r"^!$",
    r"^hostname ", r"^enable secret", r"^enable password",
    r"^service password-encryption", r"^no service password-encryption",
    r"^service timestamps", r"^no service pad",
    r"^boot-start-marker$", r"^boot-end-marker$",
    r"^line (console|con|vty)", r"^exec-timeout", r"^privilege level",
    r"^password ", r"^login( local)?$", r"^logging (synchronous|buffered|console)",
    r"^no logging console",
    r"^transport input", r"^ip domain-name", r"^ip default-gateway",
    r"^ip http server$", r"^ip http secure-server$",
    r"^vlan ", r"^name ", r"^vlan internal allocation policy",
    r"^crypto key generate", r"^ip ssh version",
    r"^interface", r"^description ", r"^duplex", r"^switchport",
    r"^no shutdown$", r"^shutdown$", r"^ip address ", r"^no ip address$",
    r"^spanning-tree", r"^clock timezone", r"^username ",
    r"^no aaa new-model$", r"^snmp-server community",
    r"^banner (motd|login)", r"^do write$", r"^end$", r"^exit$",
]


_SECRET_TYPE_MAP = {
    "0": "none",      # enable secret 0 <plaintext>
    "4": "sha256",
    "5": "md5",
    "7": "type7",
    "8": "type8",
    "9": "type9",
}


def _detect_password_encryption(config_text):
    """Strongest credential protection on the device, in rule vocabulary.

    Priority (fixes the case where 'no service password-encryption' appeared
    first and short-circuited a perfectly good 'enable secret 5 ...'):
      1. 'enable secret [<type>] <hash>' -- real devices always prefer it
         over 'enable password', and it is independent of the
         'service password-encryption' flag, which only affects type-7.
      2. 'service password-encryption' / 'no service password-encryption'
      3. bare 'enable password'
    Matching is line-anchored so comments/banners can't trigger it.
    """
    m = re.search(r"^\s*enable secret(?:\s+(\d))?\s+\S+", config_text, re.MULTILINE)
    if m:
        return _SECRET_TYPE_MAP.get(m.group(1) or "5", "md5")
    if re.search(r"^\s*no service password-encryption\s*$", config_text, re.MULTILINE):
        return "none"
    if re.search(r"^\s*service password-encryption\s*$", config_text, re.MULTILINE):
        return "type7"
    if re.search(r"^\s*enable password\s+\S+", config_text, re.MULTILINE):
        return "none"
    return None


def parse_cisco(config_text: str) -> tuple[dict, list[str]]:
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

    ssh_pattern = re.search(r"transport input (ssh|ssh telnet|telnet ssh|all)", config_text)
    telnet_pattern = re.search(r"transport input (telnet|ssh telnet|telnet ssh|all)", config_text)

    if ssh_pattern:
        fields["ssh_enabled"] = True
    elif telnet_pattern:
        fields["ssh_enabled"] = False

    if telnet_pattern:
        fields["telnet_enabled"] = True
    elif ssh_pattern:
        fields["telnet_enabled"] = False

    timeout_match = re.search(r"exec-timeout (\d+) (\d+)", config_text)
    if timeout_match:
        fields["session_timeout_seconds"] = int(timeout_match.group(1)) * 60 + int(timeout_match.group(2))

    if "no logging console" in config_text:
        fields["logging_enabled"] = False
    elif re.search(r"logging (synchronous|buffered)", config_text):
        fields["logging_enabled"] = True

    fields["password_encryption"] = _detect_password_encryption(config_text)

    fields["banner_configured"] = bool(re.search(r"banner (motd|login)", config_text))

    # Only flag communities from a known-weak/default list -- a custom,
    # properly-named community string (e.g. "Rest", "Full") is not itself
    # a finding, even though it's still configured SNMPv2c.
    KNOWN_WEAK_COMMUNITIES = {"public", "private", "cisco", "community"}
    all_communities = re.findall(r"snmp-server community (\S+)", config_text)
    if all_communities:
        weak_snmp = [c for c in all_communities if c.lower() in KNOWN_WEAK_COMMUNITIES]
        fields["snmp_default_community"] = weak_snmp

    unrecognized_lines = []
    for line in config_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not any(re.match(pat, stripped) for pat in KNOWN_LINE_PATTERNS):
            unrecognized_lines.append(stripped)

    return fields, unrecognized_lines
