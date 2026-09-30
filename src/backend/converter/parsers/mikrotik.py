"""
Block 2a - MikroTik RouterOS parser.

Handles the '/export' CLI style (paths like /ip service, /system note),
which looks nothing like Cisco/Juniper-style configs.

Confidence note: RouterOS exports never include password hashes and don't
have a clear, universal "admin idle timeout" setting the way Cisco/Junos
do, so password_encryption and session_timeout_seconds are left as None
(Not Evaluated) rather than guessed.
"""

import re


def _service_block(service: str, config_text: str) -> str | None:
    match = re.search(
        rf"^/ip service\n((?:^set .*\n)*)", config_text, re.MULTILINE
    )
    if not match:
        return None
    for line in match.group(1).splitlines():
        if re.match(rf"^set(?: \[find default=yes\])? {service}\b", line.strip()) or \
           re.search(rf"^set \d+ name={service}\b", line.strip()):
            return line
        if line.strip().startswith(f"set {service} ") or f"name={service}" in line:
            return line
    return None


def parse_mikrotik(config_text: str) -> tuple[dict, list[str]]:
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

    ssh_line = _service_block("ssh", config_text)
    if ssh_line:
        fields["ssh_enabled"] = "disabled=yes" not in ssh_line

    telnet_line = _service_block("telnet", config_text)
    if telnet_line:
        fields["telnet_enabled"] = "disabled=yes" not in telnet_line

    # /system logging action ... target=remote (a remote syslog target)
    if re.search(r"/system logging action[\s\S]*?target=remote", config_text):
        fields["logging_enabled"] = True
    elif "/system logging" in config_text:
        fields["logging_enabled"] = False

    # /system note set show-at-login=yes note="..."
    note_match = re.search(r"/system note\n((?:^set .*\n)*)", config_text, re.MULTILINE)
    if note_match:
        fields["banner_configured"] = "show-at-login=yes" in note_match.group(1)

    KNOWN_WEAK_COMMUNITIES = {"public", "private", "cisco", "community"}
    community_names = re.findall(r"/snmp community\n(?:.*\n)*?set .*?name=(\S+)", config_text)
    if not community_names:
        community_names = re.findall(r"name=(\S+)", "\n".join(
            line for line in config_text.splitlines() if "community" in line.lower()
        ))
    if community_names:
        fields["snmp_default_community"] = [
            c for c in community_names if c.lower() in KNOWN_WEAK_COMMUNITIES
        ]

    # RouterOS export sections we recognise structurally, even if we don't
    # extract a field from every line inside them.
    KNOWN_SECTION_PREFIXES = (
        "/interface", "/ip address", "/ip service", "/ip route",
        "/ip firewall", "/system", "/snmp", "/user", "/routing",
    )
    unrecognized_lines = []
    current_section_known = False
    for line in config_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("/"):
            current_section_known = stripped.startswith(KNOWN_SECTION_PREFIXES)
            if not current_section_known:
                unrecognized_lines.append(stripped)
            continue
        if not current_section_known:
            unrecognized_lines.append(stripped)

    return fields, unrecognized_lines
