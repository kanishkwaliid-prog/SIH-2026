"""
Block 2 pipeline - connects Block 2a (detection + hardcoded parsers) to
Block 2b (LLM fallback + memory).

This is the function Block 1 (frontend) and Block 3 (compliance engine)
should actually call -- everything upstream of this (converter/,
llm_classifier.py, memory.py) is internal wiring.

Follows the three-tier rule the team agreed on:
  Tier 1: hardcoded parser (converter/block2a_main.py)
  Tier 2: LLM guess (llm_classifier.py) -- ALWAYS needs human confirmation,
          never auto-applied, regardless of confidence
  Tier 3: raw lines shown to a human directly (only reached if Tier 2
          itself fails to produce any usable guess -- handled by the
          frontend when a pending_confirmation's suggested_field is
          still "unclear")
"""

from converter.block2a_main import run_block2a
from block2b.llm_classifier import classify_unknown_line, guess_vendor, confirm_classification


def process_config(config_text: str, user_declared_vendor: str = None) -> dict:
    """
    Runs the full Block 2 pipeline on a raw config file.

    Returns:
    {
        "device": {
            "vendor": str | None,
            "confidence": "high" | "low",
            "needs_confirmation": bool,
            "reason": str,
            "source": "block2a_parser" | "block2b_llm",
        },
        "config": { ...fields Block 2a resolved with certainty... },
        "pending_confirmations": [
            {
                "raw_line": str,
                "suggested_field": str,   # a NormalizedConfig field name, or "unclear"
                "suggested_value": ...,
                "confidence": float,
                "reasoning": str,
            },
            ...
        ]
    }

    "config" only ever contains values Block 2a was certain of on its own.
    Everything in "pending_confirmations" is an LLM guess and MUST be
    confirmed by a human (via apply_confirmation, below) before it's
    trustworthy -- never merge these into "config" directly.
    """
    result = run_block2a(config_text, user_declared_vendor)

    device_info = dict(result["device"])
    device_info["source"] = "block2a_parser"

    if result["escalate_to_block2b"]:
        # Tier 1 couldn't identify the vendor at all -- ask Block 2b's LLM
        # for a guess. This guess ALWAYS needs confirmation, regardless of
        # the confidence score the LLM reports.
        vendor_guess = guess_vendor(config_text)
        device_info["vendor"] = vendor_guess.get("vendor")
        device_info["confidence"] = vendor_guess.get("confidence")
        device_info["needs_confirmation"] = True
        device_info["reason"] = vendor_guess.get("reasoning", "LLM-guessed vendor")
        device_info["source"] = "block2b_llm"

    pending_confirmations = []
    config = dict(result["config"])
    for raw_line in result["unrecognized_lines"]:
        classification = classify_unknown_line(raw_line, vendor_hint=device_info.get("vendor"))
        field = classification.get("field", "unclear")

        if classification.get("confidence") == 1.0 and field != "unclear":
            # confidence == 1.0 is memory.py's signal that this exact line
            # was already confirmed by a human before (see check_memory in
            # memory.py). Auto-apply it and skip asking the human again --
            # this is the whole point of the memory layer.
            config[field] = classification.get("value")
            continue

        pending_confirmations.append({
            "raw_line": raw_line,
            "suggested_field": field,
            "suggested_value": classification.get("value"),
            "confidence": classification.get("confidence", 0.0),
            "reasoning": classification.get("reasoning"),
        })

    return {
        "device": device_info,
        "config": config,
        "pending_confirmations": pending_confirmations,
    }


def apply_confirmation(
    config: dict,
    raw_line: str,
    field: str,
    value,
    vendor_hint: str = None,
    confirmed_by: str = None,
) -> dict:
    """
    Call this once a human confirms (or corrects) one pending confirmation
    from the review screen. Two things happen:
      1. The confirmed answer is saved to memory (memory.py), so this
         exact line resolves at Tier 1/cache speed next time -- never
         hits the LLM again.
      2. If the confirmed field is a real NormalizedConfig field (not
         "unclear"), it's merged into the config dict that's passed in.

    Returns the updated config dict. Call this once per confirmed line;
    the frontend should call it for every item the human resolves on the
    review-unknown-lines screen.
    """
    confirm_classification(raw_line, field, value, vendor_hint=vendor_hint, confirmed_by=confirmed_by)

    if field and field != "unclear":
        config = dict(config)
        config[field] = value

    return config


if __name__ == "__main__":
    # Quick manual test -- run this file directly to see the full
    # pipeline (Block 2a + Block 2b) working on a real sample config.
    import json
    import sys
    from pathlib import Path

    default_sample = Path("shared/sample_configs/cisco_mixed_unrecognized.txt")
    sample_path = Path(sys.argv[1]) if len(sys.argv) > 1 else default_sample

    if not sample_path.exists():
        print(f"Sample file not found at {sample_path}")
        sys.exit(1)

    raw = sample_path.read_text()
    result = process_config(raw)
    print(json.dumps(result, indent=2))
