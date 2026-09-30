"""
Block 2a - Check Point Gaia (clish) parser.

Confidence note: Check Point Gaia configs are normally managed through
SmartConsole, not hand-edited text, so there is less public documentation
of the exact 'clish' export syntax than for Cisco/Juniper/etc. Telnet,
session timeout, banner, password hashing and SNMP below are confirmed
against Check Point's own admin guide / support articles. SSH is left as
None (Not Evaluated) because Check Point's own docs only say it's
"enabled through the WebUI", with no documented on/off clish command --
if a teammate finds the real command, add it here rather than guessing.
"""

import re

KNOWN_LINE_PATTERNS = [
    r"^set hostname", r"^set domainname", r"^set ntp",
    r"^set snmp", r"^set interface", r"^set static-route",
    r"^add ", r"^set timezone", r"^set banner",
    r"^set net-access", r"^set inactivity-timeout", r"^set user",
]


def parse_checkpoint(config_text: str) -> tuple[dict, list[str]]:
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

    if re.search(r"^set banner\s+\S", config_text, re.MULTILINE):
        fields["banner_configured"] = True

    telnet_match = re.search(r"^set net-access telnet (on|off)", config_text, re.MULTILINE)
    if telnet_match:
        fields["telnet_enabled"] = telnet_match.group(1) == "on"

    timeout_match = re.search(r"^set inactivity-timeout (\d+)", config_text, re.MULTILINE)
    if timeout_match:
        fields["session_timeout_seconds"] = int(timeout_match.group(1)) * 60

    # SSH has no confirmed on/off clish command in Check Point's own docs
    # (their admin guide says it's "enabled through the WebUI"), so
    # ssh_enabled is deliberately left as None rather than guessed.

    # Gaia stores the admin password as: set user <name> password-hash $1$...
    # "$1$" is the standard Unix MD5-crypt marker, same meaning as the
    # Palo Alto and Juniper parsers use for "md5".
    hash_match = re.search(r"password-hash\s+(\$\d\$)", config_text)
    if hash_match and hash_match.group(1) == "$1$":
        fields["password_encryption"] = "md5"

    KNOWN_WEAK_COMMUNITIES = {"public", "private", "cisco", "community"}
    all_communities = re.findall(r"^set snmp community-string (\S+)", config_text, re.MULTILINE)
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