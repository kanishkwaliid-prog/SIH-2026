"""
Shared schema definitions for the compliance pipeline.

THIS FILE IS A CONTRACT BETWEEN ALL 4 BLOCKS.
If you need to change a field name or add a field, message the team
first -- every block reads or writes this shape.

Block 2 (converter) PRODUCES a NormalizedConfig.
Block 3 (compliance engine) READS a NormalizedConfig, PRODUCES a list of Findings.
Block 4 (report generator) READS a list of Findings + DeviceInfo.
"""

from pydantic import BaseModel
from typing import Optional


class DeviceInfo(BaseModel):
    """Identifying info about the device the config came from."""
    vendor: str                    # e.g. "cisco_ios", "juniper_junos", "palo_alto"
    hostname: Optional[str] = None
    serial_number: Optional[str] = None
    os_version: Optional[str] = None
    detection_confidence: Optional[str] = None  # "high" | "medium" | "low" | "user_confirmed"


class NormalizedConfig(BaseModel):
    """
    The standard, vendor-neutral shape that every vendor's config gets
    converted into. Add fields here as the team identifies more settings
    to check -- but agree on the name/type as a team first.

    All fields are Optional because not every config will mention every
    setting -- if a setting is absent, leave it as None rather than
    guessing a default.
    """
    ssh_enabled: Optional[bool] = None
    telnet_enabled: Optional[bool] = None
    session_timeout_seconds: Optional[int] = None
    logging_enabled: Optional[bool] = None
    password_encryption: Optional[str] = None   # e.g. "type7", "md5", "none"
    banner_configured: Optional[bool] = None
    snmp_default_community: Optional[list[str]] = None   # e.g. ["public", "private"]


class Finding(BaseModel):
    """One rule's pass/fail result for one device."""
    rule_id: str                   # e.g. "CIS-4.2.1"
    status: str                    # "PASS" | "FAIL"
    severity: str                  # "low" | "medium" | "high" | "critical"
    field_checked: str             # e.g. "telnet_enabled"
    expected: str
    actual: str
    explanation: Optional[str] = None       # plain-English, can be LLM-generated
    remediation_cli: Optional[str] = None   # exact fix command(s) for this vendor


class ComplianceReport(BaseModel):
    """Full input needed by Block 4 to generate the PDF."""
    device: DeviceInfo
    framework: str                 # "CIS" | "NIST" | "STIG" | "ISO"
    findings: list[Finding]
