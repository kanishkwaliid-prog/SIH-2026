"""
Block 2a - Netgate pfSense parser.

pfSense exports its full configuration as ONE xml file (config.xml), not
line-based commands, so this parser works completely differently from the
others: it walks an XML tree instead of matching text patterns.
"""

import xml.etree.ElementTree as ET


def _find_text(root, path: str) -> str | None:
    el = root.find(path)
    if el is not None and el.text:
        return el.text.strip()
    return None


def parse_netgate_pfsense(config_text: str) -> tuple[dict, list[str]]:
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
    unrecognized_lines: list[str] = []

    try:
        root = ET.fromstring(config_text)
    except ET.ParseError as e:
        # Malformed XML -- hand the whole thing to Block 2b rather than guess.
        return fields, [f"Could not parse XML: {e}"]

    # pfSense has no telnet management daemon at all -- this is a fact
    # about the product, not a guess about this specific file's content.
    fields["telnet_enabled"] = False

    ssh_enabled = _find_text(root, "./system/enablesshd")
    if ssh_enabled is not None:
        fields["ssh_enabled"] = True
    elif root.find("./system") is not None:
        fields["ssh_enabled"] = False

    timeout_text = _find_text(root, "./system/webgui/session_timeout")
    if timeout_text and timeout_text.isdigit():
        fields["session_timeout_seconds"] = int(timeout_text) * 60

    remote_server = _find_text(root, "./syslog/remoteserver")
    if remote_server:
        fields["logging_enabled"] = True
    elif root.find("./syslog") is not None:
        fields["logging_enabled"] = False

    # pfSense stores the admin password as a bcrypt hash ("$2b$..."), a
    # strong, modern algorithm.
    password_hash = _find_text(root, "./system/user/password")
    if password_hash and password_hash.startswith("$2"):
        fields["password_encryption"] = "bcrypt"

    KNOWN_WEAK_COMMUNITIES = {"public", "private", "cisco", "community"}
    ro_community = _find_text(root, "./snmpd/rocommunity")
    if ro_community:
        fields["snmp_default_community"] = (
            [ro_community] if ro_community.lower() in KNOWN_WEAK_COMMUNITIES else []
        )

    # banner_configured has no clean pfSense equivalent (no CLI login
    # banner concept) -- left as None (Not Evaluated) rather than guessed.

    # Anything under top-level sections we don't specifically handle gets
    # flagged for the AI review step, one entry per unrecognised top-level
    # section, rather than every single leaf tag.
    KNOWN_TOP_SECTIONS = {
        "system", "syslog", "snmpd", "interfaces", "filter", "nat",
        "dhcpd", "shaper", "ca", "cert", "revision", "gateways",
    }
    for child in root:
        if child.tag not in KNOWN_TOP_SECTIONS:
            unrecognized_lines.append(f"<{child.tag}> section")

    return fields, unrecognized_lines
