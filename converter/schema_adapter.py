"""
Schema adapter — bridges the parser layer to the compliance engine.

Phase 3 deliverables:
    1. ``detect_vendor(config_text)`` — thin wrapper around codec probes
    2. ``parse_and_map(config_text)`` — parse + map to compliance JSON
    3. ``map_to_compliance_schema(intent, raw_text)`` — CanonicalIntent → dict
    4. ``unrecognized_lines`` collection for the AI fallback (Phase 5)

Compliance JSON schema::

    {
      "ssh_enabled": bool | None,
      "telnet_enabled": bool | None,
      "session_timeout_seconds": int | None,
      "logging_enabled": bool | None,
      "password_encryption": str | None,   # "none" | "type7" | "type5" | "type8" | "type9" | ...
      "banner_configured": bool | None
    }

Leave a field ``None`` when the parser can't determine the value.
Collect any config lines the parser couldn't resolve into a
separate ``unrecognized_lines`` list in the output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from converter.netcanon_migration.codecs.registry import get_codec, list_public_codecs


# ---------------------------------------------------------------------------
# 1. detect_vendor — run all codec probes, return ranked candidates
# ---------------------------------------------------------------------------

DEFAULT_PROBE_BYTES = 8000
# 8KB handles configs with long comment/HTML headers (e.g. OPNsense
# kitchen-sink has a 3.3KB XML comment block before the <opnsense> tag).


@dataclass
class VendorCandidate:
    codec: str
    confidence: int
    reason: str


def detect_vendor(
    config_text: str,
    *,
    probe_bytes: int = DEFAULT_PROBE_BYTES,
    min_confidence: int = 1,
) -> list[VendorCandidate]:
    """Run every registered codec's probe() against the first *probe_bytes*
    of *config_text* and return a ranked list of candidates.

    The top candidate is the most likely vendor/format.  Returns an
    empty list when no codec recognises the input.
    """
    prefix = config_text[:probe_bytes] if len(config_text) > probe_bytes else config_text
    candidates: list[VendorCandidate] = []

    for name in list_public_codecs():
        try:
            codec_cls = type(get_codec(name))
            result = codec_cls.probe(prefix)
        except Exception:
            continue
        if result is None:
            continue
        confidence, reason = result
        if confidence < min_confidence:
            continue
        candidates.append(VendorCandidate(
            codec=name,
            confidence=confidence,
            reason=reason,
        ))

    candidates.sort(key=lambda c: (-c.confidence, c.codec))
    return candidates


def best_vendor(
    config_text: str,
    *,
    min_confidence: int = 50,
) -> VendorCandidate | None:
    """Return the top-ranked vendor candidate, or None if below threshold."""
    ranked = detect_vendor(config_text, min_confidence=min_confidence)
    return ranked[0] if ranked else None


# ---------------------------------------------------------------------------
# 2. Raw-text heuristics for compliance fields NOT in CanonicalIntent
# ---------------------------------------------------------------------------

# --- SSH (Cisco/Arista) ---
_RE_SSH_VERSION = re.compile(r"^\s*ip\s+ssh\s+version\s+2\b", re.MULTILINE | re.IGNORECASE)
_RE_TRANSPORT_SSH = re.compile(r"^\s*transport\s+input\s+ssh\b", re.MULTILINE | re.IGNORECASE)
# FortiGate: 'set allowaccess ... ssh' on an interface
_RE_FGT_ALLOWACCESS_SSH = re.compile(
    r"^\s*set\s+allowaccess\s+.*?\bssh\b", re.MULTILINE | re.IGNORECASE
)
# OPNsense: <ssh><group>...</group></ssh> block present
_RE_OPNSENSE_SSH = re.compile(r"<ssh>\s*<group>", re.IGNORECASE)

# --- Telnet ---
_RE_TRANSPORT_TELNET = re.compile(
    r"^\s*transport\s+input\s+(?:telnet|all)\b", re.MULTILINE | re.IGNORECASE
)
# Junos: no explicit telnet disable => telnet available by default
_RE_JUNOS_TELNET_ALLOW = re.compile(
    r"^\s*set\s+system\s+services\s+telnet\b", re.MULTILINE | re.IGNORECASE
)
_RE_VYOS_TELNET = re.compile(
    r"^\s*telnet\s*\{", re.MULTILINE
)
# FortiGate: 'set allowaccess ... telnet'
_RE_FGT_ALLOWACCESS_TELNET = re.compile(
    r"^\s*set\s+allowaccess\s+.*?\btelnet\b", re.MULTILINE | re.IGNORECASE
)
# OPNsense: <telnet> block present
_RE_OPNSENSE_TELNET = re.compile(r"<telnet>", re.IGNORECASE)

# --- Session timeout ---
_RE_EXEC_TIMEOUT_IOS = re.compile(
    r"^\s*exec-timeout\s+(\d+)\s+(\d+)", re.MULTILINE
)
_RE_EXEC_TIMEOUT_JUNOS = re.compile(
    r"^\s*set\s+system\s+services\s+ssh\s+idle-timeout\s+(\d+)", re.MULTILINE
)
_RE_SESSION_TIMEOUT_MIKROTIK = re.compile(
    r"^\s*/system\s+console\s+set\s+.*?timeout=(\d+)", re.MULTILINE | re.IGNORECASE
)
_RE_TIMEOUT_VYOS = re.compile(
    r"^\s*session-timeout\s+(\d+)", re.MULTILINE
)

# --- Password encryption ---
_RE_SERVICE_PASSWORD_ENCRYPT = re.compile(
    r"^\s*service\s+password-encryption\b", re.MULTILINE | re.IGNORECASE
)
_RE_PASSWORD_TYPE = re.compile(
    r"^\s*username\s+\S+\s+.*?\s+secret\s+(\d+)\s+", re.MULTILINE | re.IGNORECASE
)
# Arista EOS uses named hash types: 'secret sha512 ...', 'secret sha256 ...'
_RE_PASSWORD_TYPE_NAMED = re.compile(
    r"^\s*username\s+\S+\s+.*?\s+secret\s+(sha(?:256|512)|md5)\s+",
    re.MULTILINE | re.IGNORECASE
)

# --- Banner ---
_RE_BANNER_MOTD = re.compile(
    r"^\s*banner\s+motd\b", re.MULTILINE | re.IGNORECASE
)
_RE_JUNOS_BANNER = re.compile(
    r"^\s*set\s+system\s+login\s+banner\s+message\b", re.MULTILINE | re.IGNORECASE
)
_RE_VYOS_BANNER = re.compile(
    r"^\s*set\s+system\s+login\s+banner\b", re.MULTILINE | re.IGNORECASE
)
_RE_MIKROTIK_BANNER = re.compile(
    r"^\s*set\s+system\s+identity\s+banner\b", re.MULTILINE | re.IGNORECASE
)

# Generic banner patterns for unknown vendors
_RE_BANNER_GENERIC = re.compile(
    r"^\s*banner\s+", re.MULTILINE | re.IGNORECASE
)


def _extract_ssh_enabled(raw: str, vendor: str) -> bool | None:
    """Determine if SSH is enabled from raw config text."""
    if vendor in ("cisco_iosxe_cli", "cisco_iosxr", "cisco_nxos", "arista_eos"):
        if _RE_SSH_VERSION.search(raw) and _RE_TRANSPORT_SSH.search(raw):
            return True
        if _RE_TRANSPORT_SSH.search(raw):
            return True
        if _RE_SSH_VERSION.search(raw):
            return True
        return None

    if vendor == "juniper_junos":
        if re.search(r"^\s*set\s+system\s+services\s+ssh\b", raw, re.MULTILINE | re.IGNORECASE):
            return True
        return None

    if vendor == "mikrotik_routeros":
        if re.search(r"^\s*/ip\s+service\s+set\s+ssh\s+.*?disabled=no", raw, re.MULTILINE | re.IGNORECASE):
            return True
        if re.search(r"^\s*/ip\s+ssh\b", raw, re.MULTILINE | re.IGNORECASE):
            return True
        return None

    if vendor in ("vyos",):
        if re.search(r"^\s*ssh\s*\{", raw, re.MULTILINE):
            return True
        return None

    # FortiGate: 'set allowaccess ... ssh' on interface
    if vendor == "fortigate_cli":
        return bool(_RE_FGT_ALLOWACCESS_SSH.search(raw))

    # OPNsense: <ssh><group> block present
    if vendor == "opnsense":
        return bool(_RE_OPNSENSE_SSH.search(raw))

    # Aruba AOS-CX: SSH service (no fixture-specific syntax, generic)
    if vendor == "aruba_aoscx":
        return None  # No SSH config in kitchen-sink fixture

    # Aruba AOS-S: SSH service (no fixture-specific syntax, generic)
    if vendor == "aruba_aoss":
        return None  # No SSH config in kitchen-sink fixture

    # Cisco IOS-XE NETCONF: only OpenConfig interfaces subtree
    if vendor == "cisco_iosxe":
        return None  # NETCONF fixture only has interface data

    return None


def _extract_telnet_enabled(raw: str, vendor: str) -> bool | None:
    """Determine if Telnet is enabled from raw config text."""
    if vendor in ("cisco_iosxe_cli", "cisco_iosxr", "cisco_nxos", "arista_eos"):
        if _RE_TRANSPORT_TELNET.search(raw):
            return True
        if _RE_TRANSPORT_SSH.search(raw):
            return False
        return None

    if vendor == "juniper_junos":
        if _RE_JUNOS_TELNET_ALLOW.search(raw):
            return True
        if re.search(r"^\s*set\s+system\s+services\s+ssh\b", raw, re.MULTILINE):
            return False
        return None

    if vendor == "vyos":
        if _RE_VYOS_TELNET.search(raw):
            return True
        return None

    # FortiGate: 'set allowaccess ... telnet'
    if vendor == "fortigate_cli":
        return bool(_RE_FGT_ALLOWACCESS_TELNET.search(raw))

    # OPNsense: <telnet> block present
    if vendor == "opnsense":
        return bool(_RE_OPNSENSE_TELNET.search(raw))

    if vendor in ("aruba_aoscx", "aruba_aoss", "cisco_iosxe"):
        return None

    return None


def _extract_session_timeout(raw: str, vendor: str) -> int | None:
    """Extract session timeout in seconds from raw config text."""
    if vendor in ("cisco_iosxe_cli", "cisco_iosxr", "cisco_nxos", "arista_eos"):
        match = _RE_EXEC_TIMEOUT_IOS.search(raw)
        if match:
            minutes = int(match.group(1))
            seconds = int(match.group(2))
            return minutes * 60 + seconds
        return None

    if vendor == "juniper_junos":
        match = _RE_EXEC_TIMEOUT_JUNOS.search(raw)
        if match:
            return int(match.group(1)) * 60
        return None

    if vendor == "vyos":
        match = _RE_TIMEOUT_VYOS.search(raw)
        if match:
            return int(match.group(1))
        return None

    # FortiGate: 'set admintimeout <minutes>'
    if vendor == "fortigate_cli":
        match = re.search(
            r"^\s*set\s+admintimeout\s+(\d+)", raw, re.MULTILINE | re.IGNORECASE
        )
        if match:
            return int(match.group(1)) * 60  # admintimeout is in minutes
        return None

    # OPNsense: no direct session timeout in config.xml
    if vendor == "opnsense":
        return None

    # MikroTik: '/system console set ... timeout=<seconds>'
    if vendor == "mikrotik_routeros":
        match = _RE_SESSION_TIMEOUT_MIKROTIK.search(raw)
        if match:
            return int(match.group(1))
        return None

    if vendor in ("aruba_aoscx", "aruba_aoss", "cisco_iosxe"):
        return None

    return None


def _extract_password_encryption(raw: str, vendor: str) -> str | None:
    """Detect password encryption type from raw config text."""
    if vendor in ("cisco_iosxe_cli", "cisco_iosxr", "cisco_nxos", "arista_eos"):
        has_service_enc = bool(_RE_SERVICE_PASSWORD_ENCRYPT.search(raw))
        # Check for Cisco numeric secret type indicators
        matches = _RE_PASSWORD_TYPE.findall(raw)
        if matches:
            types = set(matches)
            if "9" in types:
                return "type9_scrypt"
            if "8" in types:
                return "type8_pbkdf2"
            if "5" in types:
                return "type5_md5"
            if "7" in types:
                return "type7_xor"
        # Check for Arista named hash types (sha512, sha256, md5)
        named_matches = _RE_PASSWORD_TYPE_NAMED.findall(raw)
        if named_matches:
            named_types = set(t.lower() for t in named_matches)
            if "sha512" in named_types:
                return "sha512"
            if "sha256" in named_types:
                return "sha256"
            if "md5" in named_types:
                return "type5_md5"
        if has_service_enc:
            return "type7_xor"
        return None

    if vendor == "juniper_junos":
        # Junos encrypted-password uses $6$ (SHA-512) or other hashes
        if re.search(r"encrypted-password\s+\"\$6\$", raw):
            return "junos_sha512"
        if re.search(r"encrypted-password\s+\"\$1\$", raw):
            return "junos_md5"
        if re.search(r"encrypted-password", raw, re.IGNORECASE):
            return "junos_crypt"
        return None

    if vendor == "mikrotik_routeros":
        if re.search(r"^\s*set\s+\S+\s+.*?password=", raw, re.MULTILINE | re.IGNORECASE):
            return "plaintext"
        return None

    # FortiGate: 'set password ENC <hash>'
    if vendor == "fortigate_cli":
        if re.search(r"^\s*set\s+password\s+ENC\s+\S+", raw, re.MULTILINE | re.IGNORECASE):
            return "fortigate_enc"
        return None

    # OPNsense: <password>$2b$...</password> (bcrypt)
    if vendor == "opnsense":
        if re.search(r"<password>\$2[aby]\$", raw):
            return "bcrypt"
        if re.search(r"<password>", raw, re.IGNORECASE):
            return "opnsense_hash"
        return None

    # Aruba AOS-CX: 'password ciphertext <hash>'
    if vendor == "aruba_aoscx":
        if re.search(r"password\s+ciphertext\s+\S+", raw, re.IGNORECASE):
            return "aruba_ciphertext"
        return None

    # Aruba AOS-S: 'password manager user-name "<name>" sha1 "<hash>"'
    if vendor == "aruba_aoss":
        if re.search(r"password\s+\S+\s+user-name\s+.*?sha1\s+", raw, re.IGNORECASE):
            return "aruba_sha1"
        if re.search(r"password\s+\S+\s+user-name\s+.*?plaintext\s+", raw, re.IGNORECASE):
            return "aruba_plaintext"
        return None

    # Cisco IOS-XE NETCONF: only OpenConfig interfaces subtree
    if vendor == "cisco_iosxe":
        return None

    return None


def _extract_banner_configured(raw: str, vendor: str) -> bool | None:
    """Check if a login banner / MOTD is configured."""
    if vendor in ("cisco_iosxe_cli", "cisco_iosxr", "cisco_nxos", "arista_eos"):
        return bool(_RE_BANNER_MOTD.search(raw))

    if vendor == "juniper_junos":
        return bool(_RE_JUNOS_BANNER.search(raw))

    if vendor == "vyos":
        return bool(_RE_VYOS_BANNER.search(raw))

    if vendor == "mikrotik_routeros":
        return bool(_RE_MIKROTIK_BANNER.search(raw))

    # FortiGate: 'set banner "<text>"' under system global
    if vendor == "fortigate_cli":
        return bool(re.search(
            r"^\s*set\s+banner\s+\S+", raw, re.MULTILINE | re.IGNORECASE
        ))

    # OPNsense: <motd> block in system section
    if vendor == "opnsense":
        return bool(re.search(r"<motd>", raw, re.IGNORECASE))

    # Aruba: 'banner <text>' or 'header motd'
    if vendor in ("aruba_aoscx", "aruba_aoss"):
        return bool(re.search(
            r"^\s*(?:banner|header)\s+\S+", raw, re.MULTILINE | re.IGNORECASE
        ))

    # Cisco IOS-XE NETCONF: no banner in OpenConfig interfaces subtree
    if vendor == "cisco_iosxe":
        return None

    return None


# ---------------------------------------------------------------------------
# 3. Recognised vs. unrecognized line tracking
# ---------------------------------------------------------------------------

# Lines the parsers consume (rough patterns for Cisco IOS-XE CLI — the
# most common format).  Other vendors have analogous consumed-line patterns.
# This is a coarse heuristic; Phase 5 refines via AI + SQLite memory.

_CISCO_CONSUMED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*(?:hostname|domain\s+name|ip\s+domain)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:ip\s+name-server|ntp\s+server)\b", re.IGNORECASE),
    re.compile(r"^\s*logging\s+host\b", re.IGNORECASE),
    re.compile(r"^\s*interface\s+\S+", re.IGNORECASE),
    re.compile(r"^\s*vlan\s+\d+", re.IGNORECASE),
    re.compile(r"^\s*ip\s+route\b", re.IGNORECASE),
    re.compile(r"^\s*(?:snmp-server|radius|tacacs)\b", re.IGNORECASE),
    re.compile(r"^\s*username\s+\S+", re.IGNORECASE),
    re.compile(r"^\s*banner\s+\S+", re.IGNORECASE),
    re.compile(r"^\s*(?:ip\s+ssh|transport\s+input|exec-timeout)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:line\s+con|line\s+vty)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:no\s+)?shutdown\b", re.IGNORECASE),
    re.compile(r"^\s*switchport\b", re.IGNORECASE),
    re.compile(r"^\s*description\s+", re.IGNORECASE),
    re.compile(r"^\s*ip\s+address\b", re.IGNORECASE),
    re.compile(r"^\s*service\s+(?:password-encryption|timestamps)\b", re.IGNORECASE),
    re.compile(r"^\s*version\s+\d+", re.IGNORECASE),
    re.compile(r"^\s*!", re.IGNORECASE),  # Comment delimiter
    re.compile(r"^\s*end\s*$", re.IGNORECASE),
    re.compile(r"^\s*(?:no\s+)?aaa\b", re.IGNORECASE),
]


_JUNOS_CONSUMED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*set\s+system\s+(?:host-name|domain-name|time-zone|name-server|ntp|syslog|services|login|root-authentication)\b", re.IGNORECASE),
    re.compile(r"^\s*set\s+interfaces\s+\S+", re.IGNORECASE),
    re.compile(r"^\s*set\s+vlans\s+\S+", re.IGNORECASE),
    re.compile(r"^\s*set\s+routing-(?:options|instances)\b", re.IGNORECASE),
    re.compile(r"^\s*set\s+switch-options\b", re.IGNORECASE),
    re.compile(r"^\s*set\s+snmp\b", re.IGNORECASE),
    re.compile(r"^\s*set\s+access\b", re.IGNORECASE),
    re.compile(r"^\s*set\s+groups\b", re.IGNORECASE),
    re.compile(r"^\s*set\s+apply-groups\b", re.IGNORECASE),
    re.compile(r"^\s*set\s+protocols\b", re.IGNORECASE),
    re.compile(r"^\s*#", re.IGNORECASE),  # Junos comments
]

_ARISTA_CONSUMED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*(?:hostname|dns\s+domain|ip\s+name-server|ntp\s+server)\b", re.IGNORECASE),
    re.compile(r"^\s*interface\s+\S+", re.IGNORECASE),
    re.compile(r"^\s*vlan\s+\d+", re.IGNORECASE),
    re.compile(r"^\s*(?:ip|ipv6)\s+route\b", re.IGNORECASE),
    re.compile(r"^\s*(?:snmp-server|username|radius|tacacs)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:vrf\s+instance|ip\s+routing|switchport)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:description|mtu|ip\s+address|ipv6\s+address)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:no\s+)?shutdown\b", re.IGNORECASE),
    re.compile(r"^\s*(?:channel-group|spanning-tree|transceiver)\b", re.IGNORECASE),
    re.compile(r"^\s*router\s+bgp\b", re.IGNORECASE),
    re.compile(r"^\s*(?:service\s+routing|ip\s+ssh)\b", re.IGNORECASE),
    re.compile(r"^\s*end\s*$", re.IGNORECASE),
    re.compile(r"^\s*!", re.IGNORECASE),  # Comment delimiter
]


_FORTIGATE_CONSUMED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*(?:config|set|edit|end|next)\b", re.IGNORECASE),
    re.compile(r"^\s*#", re.IGNORECASE),  # FortiGate comments
]

_OPNSENSE_CONSUMED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*<\w+", re.IGNORECASE),  # Any XML tag
    re.compile(r"^\s*<!--", re.IGNORECASE),  # XML comments
]

_ARUBA_AOSCX_CONSUMED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*(?:hostname|interface|vlan|ip\s+route|user|password|switchport)\b", re.IGNORECASE),
    re.compile(r"^\s*!", re.IGNORECASE),  # Comment delimiter
]

_ARUBA_AOSS_CONSUMED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*(?:hostname|interface|vlan|ip\s+route|password|snmp|radius|user)\b", re.IGNORECASE),
    re.compile(r"^\s*;", re.IGNORECASE),  # AOS-S comments
]

# Cisco IOS-XE NETCONF: OpenConfig XML tags
_CISCO_IOSXE_XML_CONSUMED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*<\w+", re.IGNORECASE),
    re.compile(r"^\s*<!--", re.IGNORECASE),
]

_consumed_by_vendor: dict[str, list[re.Pattern[str]]] = {
    "juniper_junos": _JUNOS_CONSUMED_PATTERNS,
    "arista_eos": _ARISTA_CONSUMED_PATTERNS,
    "cisco_iosxe_cli": _CISCO_CONSUMED_PATTERNS,
    "cisco_nxos": _CISCO_CONSUMED_PATTERNS,
    "cisco_iosxr": _CISCO_CONSUMED_PATTERNS,
    "fortigate_cli": _FORTIGATE_CONSUMED_PATTERNS,
    "opnsense": _OPNSENSE_CONSUMED_PATTERNS,
    "aruba_aoscx": _ARUBA_AOSCX_CONSUMED_PATTERNS,
    "aruba_aoss": _ARUBA_AOSS_CONSUMED_PATTERNS,
    "cisco_iosxe": _CISCO_IOSXE_XML_CONSUMED_PATTERNS,
}


def _classify_lines_generic(raw: str, vendor: str = "unknown") -> tuple[list[str], list[str]]:
    """Classify config lines as consumed or unrecognized for a given vendor."""
    patterns = _consumed_by_vendor.get(vendor, _CISCO_CONSUMED_PATTERNS)
    consumed: list[str] = []
    unrecognized: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        matched = any(p.search(stripped) for p in patterns)
        if matched:
            consumed.append(stripped)
        else:
            unrecognized.append(stripped)
    return consumed, unrecognized


# ---------------------------------------------------------------------------
# 4. map_to_compliance_schema — CanonicalIntent → compliance JSON
# ---------------------------------------------------------------------------

@dataclass
class ComplianceResult:
    """Output of parse_and_map().

    NOTE on vendor vs codec vs vendor_family:
    - ``vendor`` is the specific codec identifier (e.g. "cisco_iosxe_cli"),
      and is what remediation-CLI lookups in the compliance rule pack
      (Phase 4) should key off, since different codecs of the same
      vendor family can parse completely different config surfaces
      (CLI text vs NETCONF/XML) and need different remediation commands.
    - ``codec`` is kept identical to ``vendor`` for backwards
      compatibility with anything already reading it.
    - ``vendor_family`` is the generic vendor label Netcanon's canonical
      model uses internally (e.g. "cisco_iosxe" for both the CLI and
      NETCONF codecs of that family) -- use this only for display
      purposes ("Cisco IOS-XE"), never for remediation lookups.
    """
    vendor: str
    codec: str
    confidence: int
    vendor_family: str | None = None
    ssh_enabled: bool | None = None
    telnet_enabled: bool | None = None
    session_timeout_seconds: int | None = None
    logging_enabled: bool | None = None
    password_encryption: str | None = None
    banner_configured: bool | None = None
    unrecognized_lines: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "codec": self.codec,
            "vendor_family": self.vendor_family,
            "confidence": self.confidence,
            "ssh_enabled": self.ssh_enabled,
            "telnet_enabled": self.telnet_enabled,
            "session_timeout_seconds": self.session_timeout_seconds,
            "logging_enabled": self.logging_enabled,
            "password_encryption": self.password_encryption,
            "banner_configured": self.banner_configured,
            "unrecognized_lines": self.unrecognized_lines,
            "error": self.error,
        }


def map_to_compliance_schema(
    intent: Any,
    raw_text: str,
    vendor: str,
) -> dict[str, Any]:
    """Map a CanonicalIntent + raw config text to the compliance JSON schema.

    Fields that the canonical model populates are read from *intent*.
    Fields that need raw-text heuristics (SSH, telnet, session timeout,
    banner, password encryption) are extracted from *raw_text* using
    vendor-aware regexes.

    Returns a dict matching the compliance JSON schema plus an
    ``unrecognized_lines`` list.
    """
    # --- Fields derivable from CanonicalIntent ---
    # logging_enabled: syslog_servers being non-empty suggests logging is configured
    logging_enabled: bool | None = None
    if hasattr(intent, "syslog_servers") and intent.syslog_servers:
        logging_enabled = True

    # Also check for logging hosts in raw text as a fallback
    if logging_enabled is None and raw_text:
        if re.search(r"^\s*logging\s+host\b", raw_text, re.MULTILINE | re.IGNORECASE):
            logging_enabled = True
        # Junos: 'set system syslog host'
        if re.search(r"^\s*set\s+system\s+syslog\s+host\b", raw_text, re.MULTILINE | re.IGNORECASE):
            logging_enabled = True
        # OPNsense: <syslog> block present
        if re.search(r"<syslog>", raw_text, re.IGNORECASE):
            logging_enabled = True
        # FortiGate: 'set log setting' or 'config log'
        if re.search(r"^\s*(?:set\s+log|config\s+log)\b", raw_text, re.MULTILINE | re.IGNORECASE):
            logging_enabled = True
        # Aruba: 'logging' command present
        if re.search(r"^\s*logging\b", raw_text, re.MULTILINE | re.IGNORECASE):
            logging_enabled = True

    # --- Fields requiring raw-text heuristics ---
    ssh_enabled = _extract_ssh_enabled(raw_text, vendor) if raw_text else None
    telnet_enabled = _extract_telnet_enabled(raw_text, vendor) if raw_text else None
    session_timeout = _extract_session_timeout(raw_text, vendor) if raw_text else None
    password_enc = _extract_password_encryption(raw_text, vendor) if raw_text else None
    banner = _extract_banner_configured(raw_text, vendor) if raw_text else None

    # --- Unrecognized lines ---
    _, unrecognized = _classify_lines_generic(raw_text, vendor) if raw_text else ([], [])

    return {
        "ssh_enabled": ssh_enabled,
        "telnet_enabled": telnet_enabled,
        "session_timeout_seconds": session_timeout,
        "logging_enabled": logging_enabled,
        "password_encryption": password_enc,
        "banner_configured": banner,
        "unrecognized_lines": unrecognized,
    }


# ---------------------------------------------------------------------------
# 5. Full pipeline: parse + map
# ---------------------------------------------------------------------------

def parse_and_map(config_text: str) -> ComplianceResult:
    """End-to-end: detect vendor → parse → map to compliance schema.

    This is the main entry point for the compliance pipeline.
    """
    # Step 1: Detect vendor
    candidates = detect_vendor(config_text)
    if not candidates:
        return ComplianceResult(
            vendor="unknown",
            codec="none",
            confidence=0,
            error="No codec recognised the input format.",
        )

    best = candidates[0]

    # Step 2: Parse
    try:
        codec = get_codec(best.codec)
        intent = codec.parse(config_text)
    except Exception as e:
        return ComplianceResult(
            vendor=best.codec,
            codec=best.codec,
            confidence=best.confidence,
            error=f"Parse failed: {e}",
        )

    # Step 3: Map to compliance schema
    schema = map_to_compliance_schema(intent, config_text, best.codec)

    return ComplianceResult(
        vendor=best.codec,
        codec=best.codec,
        confidence=best.confidence,
        vendor_family=getattr(intent, "source_vendor", None) or best.codec,
        ssh_enabled=schema["ssh_enabled"],
        telnet_enabled=schema["telnet_enabled"],
        session_timeout_seconds=schema["session_timeout_seconds"],
        logging_enabled=schema["logging_enabled"],
        password_encryption=schema["password_encryption"],
        banner_configured=schema["banner_configured"],
        unrecognized_lines=schema["unrecognized_lines"],
    )
