"""
Block 2a - Huawei VRP parser.

Handles the standard Huawei VRP CLI export style (used by Huawei switches
and routers, and closely-related H3C Comware devices for some commands).
"""

import re

KNOWN_LINE_PATTERNS = [
    r"^#", r"^sysname ", r"^aaa$", r"^local-user ", r"^quit$",
    r"^stelnet server enable$", r"^undo telnet server enable$",
    r"^user-interface", r"^protocol inbound", r"^idle-timeout",
    r"^authentication-mode", r"^info-center", r"^undo info-center",
    r"^header (login|shell)", r"^snmp-agent",
    r"^interface", r"^description ", r"^ip address ", r"^undo shutdown$",
    r"^shutdown$", r"^vlan ", r"^return$",
]


def parse_huawei(config_text: str) -> tuple[dict, list[str]]:
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

    if "stelnet server enable" in config_text:
        fields["ssh_enabled"] = True

    telnet_match = re.search(r"protocol inbound (telnet|ssh|all)", config_text)
    if telnet_match:
        proto = telnet_match.group(1)
        fields["telnet_enabled"] = proto in ("telnet", "all")
        if proto in ("ssh", "all"):
            fields["ssh_enabled"] = True
    elif "undo telnet server enable" in config_text:
        fields["telnet_enabled"] = False

    # idle-timeout <minutes> <seconds>, set inside a user-interface block
    timeout_match = re.search(r"idle-timeout (\d+)(?: (\d+))?", config_text)
    if timeout_match:
        minutes = int(timeout_match.group(1))
        seconds = int(timeout_match.group(2) or 0)
        fields["session_timeout_seconds"] = minutes * 60 + seconds

    if "undo info-center enable" in config_text:
        fields["logging_enabled"] = False
    elif "info-center enable" in config_text or re.search(r"info-center loghost", config_text):
        fields["logging_enabled"] = True

    # Huawei marks stored passwords as "cipher" (encrypted) or "simple"
    # (plaintext) right in the local-user / password line.
    if re.search(r"password (irreversible-cipher|cipher)\s", config_text):
        fields["password_encryption"] = "cipher"
    elif re.search(r"password simple\s", config_text):
        fields["password_encryption"] = "none"

    fields["banner_configured"] = bool(re.search(r"header (login|shell)", config_text))

    KNOWN_WEAK_COMMUNITIES = {"public", "private", "cisco", "community"}
    all_communities = re.findall(r"snmp-agent community (?:read|write) (?:cipher )?(\S+)", config_text)
    if all_communities:
        fields["snmp_default_community"] = [
            c for c in all_communities if c.lower() in KNOWN_WEAK_COMMUNITIES
        ]

    unrecognized_lines = []
    for line in config_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not any(re.match(pat, stripped) for pat in KNOWN_LINE_PATTERNS):
            unrecognized_lines.append(stripped)

    return fields, unrecognized_lines
