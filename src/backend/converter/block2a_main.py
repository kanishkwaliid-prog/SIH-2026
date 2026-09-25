"""
Block 2a - Main entry point.

This is the ONE function other blocks (and eventually main.py) should
call. Everything else in converter/ is an internal implementation
detail.
"""

from .detection import resolve_vendor
from .parsers import PARSER_DISPATCH


def run_block2a(config_text: str, user_declared_vendor: str | None = None) -> dict:
    """
    Runs vendor detection + known-vendor parsing on a raw config file.

    Returns a dict shaped like:
    {
        "device": {
            "vendor": "cisco_ios" | None,
            "confidence": "high" | "low",
            "needs_confirmation": bool,
            "reason": str,
        },
        "config": { ...known fields, possibly with None values... },
        "unrecognized_lines": [ ...lines Block 2b needs to handle... ],
        "escalate_to_block2b": bool,  # True if vendor itself is unknown
    }

    If the vendor can't be confidently identified at all, "config" will
    be empty and "unrecognized_lines" will contain the whole file --
    Block 2b's LLM should attempt vendor identification in that case.
    """
    vendor_result = resolve_vendor(config_text, user_declared_vendor)

    device_info = {
        "vendor": vendor_result["vendor"],
        "confidence": vendor_result["confidence"],
        "needs_confirmation": vendor_result["needs_confirmation"],
        "reason": vendor_result["reason"],
    }

    if vendor_result["escalate_to_block2b"] or vendor_result["vendor"] is None:
        # No confident vendor match -- nothing to parse yet, hand the
        # whole file to Block 2b for an LLM-assisted guess.
        return {
            "device": device_info,
            "config": {},
            "unrecognized_lines": config_text.splitlines(),
            "escalate_to_block2b": True,
        }

    parser_fn = PARSER_DISPATCH.get(vendor_result["vendor"])
    if parser_fn is None:
        # Detected a vendor name we don't have a parser for yet
        return {
            "device": device_info,
            "config": {},
            "unrecognized_lines": config_text.splitlines(),
            "escalate_to_block2b": True,
        }

    fields, unrecognized_lines = parser_fn(config_text)

    return {
        "device": device_info,
        "config": fields,
        "unrecognized_lines": unrecognized_lines,
        "escalate_to_block2b": False,
    }


if __name__ == "__main__":
    # Quick manual test -- run this file directly to sanity-check against
    # the sample configs in shared/sample_configs/
    import json
    import sys
    from pathlib import Path

    sample_path = Path(__file__).parent.parent / "shared" / "sample_configs" / "sample_raw_cisco.txt"
    if sample_path.exists():
        raw = sample_path.read_text()
        result = run_block2a(raw)
        print(json.dumps(result, indent=2))
    else:
        print(f"Sample file not found at {sample_path} -- adjust the path and try again.")
