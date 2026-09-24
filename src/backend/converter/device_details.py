"""
Block 2a - Device details.

Pulls hostname / OS version / hardware model / management IP out of a raw
config file, but ONLY when the file actually contains them. Serial numbers
are almost never stored in a config file, so they are only filled in when
a clear line exists. Anything not found is simply left out (the report then
shows it as "not in config file").
"""

import re


def _first(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1).strip() if match else None


def extract_device_details(vendor: str | None, config_text: str) -> dict:
    """Returns a dict with any of: hostname, os_version, hardware_model,
    serial_number, ip_address. Missing values are not included."""
    details: dict = {}

    if vendor == "cisco_ios":
        details["hostname"] = _first(r"^hostname (\S+)", config_text)
        details["os_version"] = _first(r"^version (\S+)", config_text)
        details["serial_number"] = _first(
            r"(?i)(?:processor board id|system serial number)[: ]+(\S+)", config_text
        )

    elif vendor == "juniper_junos":
        details["hostname"] = _first(r"^set system host-name (\S+)", config_text)
        details["os_version"] = _first(r"^set version (\S+)", config_text)

    elif vendor == "palo_alto":
        details["hostname"] = _first(r"^set deviceconfig system hostname (\S+)", config_text)
        details["ip_address"] = _first(r"^set deviceconfig system ip-address (\S+)", config_text)

    elif vendor == "fortinet_fortios":
        # Header looks like: #config-version=FGVM64-7.2.4-FW-build1396-...
        header = re.search(
            r"^#config-version=([A-Za-z0-9]+)-(\d+\.\d+\.\d+)", config_text, re.MULTILINE
        )
        if header:
            details["hardware_model"] = header.group(1)
            details["os_version"] = header.group(2)
        details["hostname"] = _first(r'^\s*set hostname "?([^"\n]+)"?', config_text)

    return {key: value for key, value in details.items() if value}