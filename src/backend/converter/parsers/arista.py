"""
Block 2a - Arista EOS parser.

Arista EOS's CLI is deliberately close to Cisco IOS, so most patterns are
shared. A few things are Arista-specific (management ssh/telnet blocks,
the way secrets are hashed) and are handled separately below.
"""

import re

KNOWN_LINE_PATTERNS = [
    r"^!", r"^hostname ", r"^no aaa root", r"^aaa authentication",
    r"^username ", r"^management api http-commands", r"^management ssh",
    r"^management telnet", r"^management console",
    r"^service password-encryption", r"^no service password-encryption",
    r"^line (con|vty)", r"^exec-timeout", r"^login( local)?$", r"^password ",
    r"^logging ", r"^no logging",
    r"^interface", r"^description ", r"^switchport", r"^no switchport",
    r"^ip address ", r"^no ip address$", r"^shutdown$", r"^no shutdown$",
    r"^vlan ", r"^name ", r"^spanning-tree", r"^snmp-server community",
    r"^banner (motd|login)", r"^end$", r"^exit$", r"^no shutdown",
]


def _mgmt_block_status(block_name: str, config_text: str) -> bool | None:
    """Reads the 'shutdown'/'no shutdown' line inside a management block."""
    match = re.search(
        rf"^management {block_name}\n((?:^ {{1,4}}\S.*\n)*)", config_text, re.MULTILINE
    )
    if not match:
        return None
    body = match.group(1)
    if re.search(r"^\s*no shutdown", body, re.MULTILINE):
        return True
    if re.search(r"^\s*shutdown", body, re.MULTILINE):
        return False
    return None


def parse_arista(config_text: str) -> tuple[dict, list[str]]:
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

    ssh_block = _mgmt_block_status("ssh", config_text)
    telnet_block = _mgmt_block_status("telnet", config_text)
    if ssh_block is not None:
        fields["ssh_enabled"] = ssh_block
    if telnet_block is not None:
        fields["telnet_enabled"] = telnet_block

    # Fallback: same "transport input" style Cisco uses on line vty, in
    # case management ssh/telnet blocks aren't present in the file.
    if fields["ssh_enabled"] is None or fields["telnet_enabled"] is None:
        ssh_t = re.search(r"transport input (ssh|ssh telnet|telnet ssh|all)", config_text)
        telnet_t = re.search(r"transport input (telnet|ssh telnet|telnet ssh|all)", config_text)
        if fields["ssh_enabled"] is None and ssh_t:
            fields["ssh_enabled"] = True
        if fields["telnet_enabled"] is None and telnet_t:
            fields["telnet_enabled"] = True

    timeout_match = re.search(r"exec-timeout (\d+) (\d+)", config_text)
    if timeout_match:
        fields["session_timeout_seconds"] = int(timeout_match.group(1)) * 60 + int(timeout_match.group(2))

    if "no logging console" in config_text:
        fields["logging_enabled"] = False
    elif re.search(r"^logging (host|console|buffered)", config_text, re.MULTILINE):
        fields["logging_enabled"] = True

    # Arista stores secrets as: username <name> secret <type> <hash>
    # type 0 = cleartext, 5 = md5, 7 = reversible (like Cisco type 7),
    # sha512 = modern/strong.
    secret_match = re.search(r"username \S+ (?:privilege \d+ )?secret (0|5|7|sha512)\s", config_text)
    if secret_match:
        kind = secret_match.group(1)
        fields["password_encryption"] = {
            "0": "none", "7": "type7", "5": "md5", "sha512": "sha512",
        }[kind]

    fields["banner_configured"] = bool(re.search(r"banner (motd|login)", config_text))

    KNOWN_WEAK_COMMUNITIES = {"public", "private", "cisco", "community"}
    all_communities = re.findall(r"snmp-server community (\S+)", config_text)
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
