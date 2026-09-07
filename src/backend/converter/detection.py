"""
Block 2a - Vendor detection.

Looks at raw config text and guesses which vendor wrote it, using
structural signatures (no AI/ML needed for this part -- just pattern
matching). Returns a confidence level so the rest of the pipeline knows
whether human confirmation is needed.

Confidence levels:
  "high"   - strong, unambiguous signature match
  "low"    - no known vendor matched; Block 2b (LLM) should take over
"""

import re


def detect_vendor(config_text: str) -> tuple[str, str, str]:
    """
    Returns (vendor, confidence, reason).

    vendor is one of: "cisco_ios", "juniper_junos", "palo_alto", "unknown"
    reason is a short human-readable explanation, shown in the frontend's
    confirmation screen so the user understands *why* this was guessed.
    """
    stripped = config_text.strip()

    # Palo Alto: either raw XML config export, or 'set deviceconfig' CLI style
    if stripped.startswith("<?xml") or "<entry name=" in stripped:
        return "palo_alto", "high", "Detected XML config structure"
    if re.search(r"^set deviceconfig", stripped, re.MULTILINE):
        return "palo_alto", "high", "Detected 'set deviceconfig' PAN-OS syntax"

    # Juniper: 'set system' / 'set security' CLI style, or curly-brace hierarchy
    if re.search(r"^set (system|security|interfaces|routing-options)", stripped, re.MULTILINE):
        return "juniper_junos", "high", "Detected Junos 'set' command syntax"
    if re.search(r"^\s*system\s*\{", stripped, re.MULTILINE):
        return "juniper_junos", "high", "Detected curly-brace hierarchical syntax"

    # Cisco IOS: line vty/con blocks are a strong, near-unique signature
    if re.search(r"^line (vty|con)", stripped, re.MULTILINE):
        return "cisco_ios", "high", "Detected 'line vty/con' block syntax"

    return "unknown", "low", "No known vendor signature matched"


def resolve_vendor(
    config_text: str,
    user_declared_vendor: str | None = None,
) -> dict:
    """
    Combines detection with an optional user-declared vendor to decide
    which vendor to actually parse with, and whether the frontend needs
    to show a confirmation screen.

    This implements the rule the team agreed on:
    confirmation is required whenever the DETECTOR itself isn't
    confident -- regardless of whether the user supplied a vendor name.
    """
    detected_vendor, confidence, reason = detect_vendor(config_text)

    if confidence == "low":
        # Detector has no confident answer -- Block 2b's LLM guess should
        # be used instead. Signal this clearly to the caller.
        return {
            "vendor": None,
            "confidence": "low",
            "needs_confirmation": True,
            "reason": reason,
            "escalate_to_block2b": True,
        }

    if user_declared_vendor and user_declared_vendor != detected_vendor:
        # Mismatch: user claimed one vendor, detector confidently found another
        return {
            "vendor": detected_vendor,
            "confidence": confidence,
            "needs_confirmation": True,
            "reason": f"You selected '{user_declared_vendor}', but {reason.lower()} "
                      f"consistent with '{detected_vendor}'.",
            "escalate_to_block2b": False,
            "user_declared_vendor": user_declared_vendor,
        }

    # Either no hint was given and detection is confident, or the hint
    # matches detection -- both cases proceed without confirmation.
    return {
        "vendor": detected_vendor,
        "confidence": confidence,
        "needs_confirmation": False,
        "reason": reason,
        "escalate_to_block2b": False,
    }
