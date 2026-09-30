"""
Block 2a - Netgate pfSense parser.

pfSense exports config as XML, not lines. Field mapping is still to be
filled in from a real config.xml.
"""

import xml.etree.ElementTree as ET


def parse_pfsense(config_text: str) -> tuple[dict, list[str]]:
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

    # Sanity check that the XML is well formed. No field mapping yet.
    root = ET.fromstring(config_text)
    system = root.find("system")
    if system is not None:
        # Presence of <enablesshd> means SSH is on. Newer versions may use
        # <ssh><enable>, so check both. Absence is left as None, not False,
        # because we haven't confirmed that absence means disabled.
        if system.find("enablesshd") is not None or system.findtext("ssh/enable"):
            fields["ssh_enabled"] = True
                # pfSense stores the GUI session timeout in minutes at
        # system/webgui/session_timeout. Convert to seconds.
        # Absence is left as None: the GUI default (240 min) applies,
        # but we haven't confirmed that, so we don't assume it.
        timeout_text = system.findtext("webgui/session_timeout")
        if timeout_text and timeout_text.strip().isdigit():
            fields["session_timeout_seconds"] = int(timeout_text.strip()) * 60
        # <snmpd> is a top-level section. The <rocommunity> child tag is
    # unverified against a real pfSense export, so recheck it later.
    # True means the community is a well-known default. Absence stays None.
    snmpd = root.find("snmpd")
    if snmpd is not None:
        community = (snmpd.findtext("rocommunity") or "").strip().lower()
        if community:
            fields["snmp_default_community"] = community in ("public", "private")

    return fields, []
    