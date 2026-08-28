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

    if "no service password-encryption" in config_text:
        fields["password_encryption"] = "none"
    elif "service password-encryption" in config_text:
        fields["password_encryption"] = "type7"
    elif "enable secret" in config_text and "enable password" not in config_text:
        fields["password_encryption"] = "md5"
    elif "enable password" in config_text:
        fields["password_encryption"] = "none"

    fields["banner_configured"] = bool(re.search(r"banner (motd|login)", config_text))

    weak_snmp = re.findall(r"snmp-server community (\S+)", config_text)
    if weak_snmp:
        fields["snmp_default_community"] = weak_snmp

    unrecognized_lines = []
    for line in config_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not any(re.match(pat, stripped) for pat in KNOWN_LINE_PATTERNS):
            unrecognized_lines.append(stripped)

    return fields, unrecognized_lines
