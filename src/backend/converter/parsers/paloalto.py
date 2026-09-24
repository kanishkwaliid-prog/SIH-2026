"""
Block 2a - Palo Alto PAN-OS parser.

Handles the 'set deviceconfig' CLI style. XML export format is not yet
handled -- flag to the team if you encounter one.
"""

import re

KNOWN_LINE_PATTERNS = [
    r"^set deviceconfig system",
    # Structural PAN-OS sections that are common but not yet mapped to
    # a NormalizedConfig field -- flagging these as "known" (rather than
    # unrecognized) keeps routine interface/zone/policy/NAT config from
    # flooding Block 2b with lines that aren't actually ambiguous, just
    # not yet extracted into a field. This list is NOT exhaustive --
    # add to it as real PAN-OS configs surface new top-level sections.
    r"^set network", r"^set zone", r"^set rulebase",
    r"^set shared", r"^set mgt-config", r"^set vsys",
    r"^set address", r"^set service",
]


def parse_paloalto(config_text: str) -> tuple[dict, list[str]]:
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
    has_system_section = "set deviceconfig system" in config_text
    if "disable-telnet yes" in config_text:
        fields["telnet_enabled"] = False
    elif "disable-telnet no" in config_text:
        fields["telnet_enabled"] = True

    if "disable-ssh yes" in config_text:
        fields["ssh_enabled"] = False
    elif "disable-ssh no" in config_text:
        fields["ssh_enabled"] = True

    idle_match = re.search(r"idle-timeout (\d+)", config_text)
    if idle_match:
        fields["session_timeout_seconds"] = int(idle_match.group(1)) * 60

        

    if re.search(r"deviceconfig system login-banner\s+\S", config_text):
        fields["banner_configured"] = True
    elif has_system_section:
        fields["banner_configured"] = False

    if re.search(r"log-settings\s+syslog", config_text):
        fields["logging_enabled"] = True
    elif has_system_section:
        fields["logging_enabled"] = False
    
    phash_match = re.search(r'mgt-config users \S+ phash\s+"?(\$\w+\$)', config_text)
    if phash_match:
        if phash_match.group(1) == "$1$":
            fields["password_encryption"] = "md5"

    KNOWN_WEAK_COMMUNITIES = {"public", "private", "cisco", "community"}
    all_communities = re.findall(r'snmp-community-string\s+"?([^\s"]+)', config_text)
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
