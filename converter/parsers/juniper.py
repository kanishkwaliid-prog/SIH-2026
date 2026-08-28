"""
Block 2a - Juniper Junos parser.

Handles the 'set' command style (e.g. `set system services ssh`).
Curly-brace hierarchical style is not yet handled -- flag to the team
if you encounter one, it'll need a separate parsing approach.
"""

import re

KNOWN_LINE_PATTERNS = [
    r"^set system host-name", r"^set system name-server",
    r"^set system services", r"^set system syslog",
    r"^set system login", r"^set system max-configuration",
    r"^set interfaces", r"^set routing-options",
    r"^set security zones", r"^set security policies",
]


def parse_juniper(config_text: str) -> tuple[dict, list[str]]:
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

    if "set system services ssh" in config_text:
        fields["ssh_enabled"] = True

    if "set system services telnet" in config_text:
        fields["telnet_enabled"] = True
    elif "set system services ssh" in config_text:
        fields["telnet_enabled"] = False

    if "set system syslog" in config_text:
        fields["logging_enabled"] = True

    timeout_match = re.search(r"set system login idle-timeout (\d+)", config_text)
    if timeout_match:
        fields["session_timeout_seconds"] = int(timeout_match.group(1)) * 60

    fields["banner_configured"] = "set system login message" in config_text

    unrecognized_lines = []
    for line in config_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not any(re.match(pat, stripped) for pat in KNOWN_LINE_PATTERNS):
            unrecognized_lines.append(stripped)

    return fields, unrecognized_lines
