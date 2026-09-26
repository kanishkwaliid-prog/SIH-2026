"""
Block 2a - SONiC (config_db.json) parser.

SONiC stores its configuration as ONE json file (config_db.json), a
dictionary of tables, not text commands -- so like the pfSense parser,
this one reads structured data instead of matching lines.

Confidence note: SONiC has no telnet daemon and no config-file concept of
an "admin idle timeout" or a login banner the way Cisco/Junos do, and
passwords aren't stored in config_db.json at all (they live in the Linux
user database). Those fields are left as None (Not Evaluated) rather than
guessed, except telnet, which is a known fact about the product (see the
pfSense parser for the same reasoning).
"""

import json


def parse_sonic(config_text: str) -> tuple[dict, list[str]]:
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
        data = json.loads(config_text)
    except json.JSONDecodeError as e:
        return fields, [f"Could not parse JSON: {e}"]

    if not isinstance(data, dict):
        return fields, ["Top-level JSON is not an object -- unexpected config_db.json shape"]

    # SONiC ships no telnet daemon in the standard image -- a fact about
    # the product, not something we're reading from this specific file.
    fields["telnet_enabled"] = False

    syslog_table = data.get("SYSLOG_SERVER")
    if syslog_table is not None:
        fields["logging_enabled"] = bool(syslog_table)

    KNOWN_WEAK_COMMUNITIES = {"public", "private", "cisco", "community"}
    snmp_table = data.get("SNMP_COMMUNITY")
    if snmp_table is not None:
        fields["snmp_default_community"] = [
            name for name in snmp_table.keys() if name.lower() in KNOWN_WEAK_COMMUNITIES
        ]

    KNOWN_TABLES = {
        "DEVICE_METADATA", "SYSLOG_SERVER", "SNMP_COMMUNITY", "NTP_SERVER",
        "NTP", "INTERFACE", "PORT", "VLAN", "VLAN_MEMBER", "MGMT_INTERFACE",
        "MGMT_PORT", "LOOPBACK_INTERFACE", "BGP_NEIGHBOR", "STP", "ACL_TABLE",
        "ACL_RULE", "FEATURE", "AAA", "TACPLUS", "TACPLUS_SERVER",
    }
    for key in data.keys():
        if key not in KNOWN_TABLES:
            unrecognized_lines.append(f'"{key}" table')

    return fields, unrecognized_lines
