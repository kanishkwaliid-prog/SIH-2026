"""
Block 2a - Palo Alto PAN-OS parser.

Handles the 'set deviceconfig' CLI style. XML export format is not yet
handled -- flag to the team if you encounter one.
"""

import re

KNOWN_LINE_PATTERNS = [
    r"^set deviceconfig system",
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

    if "disable-telnet yes" in config_text:
        fields["telnet_enabled"] = False
    elif "disable-telnet no" in config_text:
        fields["telnet_enabled"] = True

    # PAN-OS doesn't have a clear "enable ssh" line, so we leave this
    # blank instead of guessing, same as the other fields.

    idle_match = re.search(r"idle-timeout (\d+)", config_text)
    if idle_match:
        fields["session_timeout_seconds"] = int(idle_match.group(1)) * 60

    unrecognized_lines = []
    for line in config_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not any(re.match(pat, stripped) for pat in KNOWN_LINE_PATTERNS):
            unrecognized_lines.append(stripped)

    return fields, unrecognized_lines
