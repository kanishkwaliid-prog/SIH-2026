"""
ai_fallback.classify
---------------------
Phase 5 — AI-assisted classification of config lines the converter
couldn't recognise (``ComplianceResult.unrecognized_lines``), backed by
the persistent memory in ``ai_fallback.memory`` so a pattern that's
already been confirmed once is never re-sent to the AI or re-asked of a
human.

Pipeline for a batch of unrecognized lines from one device:

    1. check memory (``MemoryStore.check_known_mapping``) for every line
    2. only the misses go to the Claude API, batched into ONE call
    3. results are returned tagged ``needs_confirmation`` -- this module
       never writes anything into ``NormalizedConfig`` /
       ``ComplianceResult`` and never auto-applies an AI guess. Phase
       5.6's review screen is expected to call
       ``confirm_classification()`` once a human accepts or corrects a
       guess, which is the only thing that persists it to memory.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Callable, Optional

from ai_fallback.memory import MemoryStore, VALID_CATEGORIES

DEFAULT_MODEL = "claude-sonnet-4-6"

# Signature of the injectable "make one Claude API call" function:
# (vendor, lines_to_classify, model) -> raw text of the model's reply.
# Tests (and any offline/dry-run usage) pass a fake implementation here
# so nothing in this module requires network access or an API key
# unless the real path is actually used.
ApiCallFn = Callable[[str, list[str], str], str]


class ClassifierError(RuntimeError):
    """Raised when the AI response can't be parsed into per-line guesses."""


@dataclass(frozen=True)
class LineClassification:
    raw_line: str
    category: str              # one of ai_fallback.memory.VALID_CATEGORIES
    confidence: int            # 0-100
    source: str                # "memory" | "ai"
    needs_confirmation: bool   # False only for memory hits

    def to_review_dict(self) -> dict:
        """Shape expected by the Phase 5.6 human-review screen:
        {raw_line, ai_guess, confidence} plus bookkeeping fields."""
        d = asdict(self)
        d["ai_guess"] = d.pop("category")
        return d


def _default_api_call(vendor: str, lines: list[str], model: str) -> str:
    """Real Claude API call. `anthropic` is imported lazily so importing
    this module never requires the package or a configured API key
    unless this code path actually runs."""
    import anthropic  # optional dependency, only needed for real calls

    client = anthropic.Anthropic()
    prompt = _build_classification_prompt(vendor, lines)
    response = client.messages.create(
        model=model,
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(
        block.text for block in response.content
        if getattr(block, "type", None) == "text"
    )


def _build_classification_prompt(vendor: str, lines: list[str]) -> str:
    categories = ", ".join(sorted(VALID_CATEGORIES))
    numbered = "\n".join(f"{i}: {line}" for i, line in enumerate(lines))
    return (
        f"You are classifying unrecognized lines from a {vendor} network "
        f"device configuration file into compliance-check categories.\n\n"
        f"Categories: {categories}\n\n"
        "For each numbered line below, decide which single category it "
        "most likely relates to, or \"unclear\" if none fit. Respond with "
        "ONLY a JSON array, no other text, one object per line, in the "
        "same order, each shaped exactly like:\n"
        '{"index": <int>, "category": "<one of the categories above>", '
        '"confidence": <integer 0-100>}\n\n'
        f"Lines:\n{numbered}"
    )


def _parse_classifier_response(raw_response: str, expected_count: int) -> list[dict]:
    text = raw_response.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        raise ClassifierError(
            f"AI response was not valid JSON: {e}\nRaw: {raw_response!r}"
        ) from e

    if not isinstance(parsed, list):
        raise ClassifierError(f"Expected a JSON array, got {type(parsed).__name__}")
    if len(parsed) != expected_count:
        raise ClassifierError(
            f"Expected {expected_count} classifications, got {len(parsed)}"
        )

    for item in parsed:
        if not isinstance(item, dict) or not {"index", "category", "confidence"} <= item.keys():
            raise ClassifierError(f"Malformed classification entry: {item!r}")
        if item["category"] not in VALID_CATEGORIES:
            raise ClassifierError(
                f"AI returned unknown category '{item['category']}' "
                f"(expected one of {sorted(VALID_CATEGORIES)})"
            )
        if not isinstance(item["confidence"], int) or not (0 <= item["confidence"] <= 100):
            raise ClassifierError(f"Invalid confidence in {item!r}")

    return sorted(parsed, key=lambda d: d["index"])


def classify_unrecognized_lines(
    vendor: str,
    lines: list[str],
    memory: MemoryStore,
    api_call_fn: Optional[ApiCallFn] = None,
    model: str = DEFAULT_MODEL,
) -> list[LineClassification]:
    """Classify a batch of unrecognized lines for one device/vendor.

    Memory is checked first for every line; only misses are sent to the
    AI, in a single batched call (never one call per line). Returns
    results in the same order as *lines*. Nothing is persisted here --
    call ``confirm_classification()`` after a human reviews the AI
    guesses.
    """
    api_call_fn = api_call_fn or _default_api_call

    results: list[Optional[LineClassification]] = [None] * len(lines)
    miss_indices: list[int] = []
    miss_lines: list[str] = []

    for i, line in enumerate(lines):
        known = memory.check_known_mapping(vendor, line)
        if known is not None:
            results[i] = LineClassification(
                raw_line=line,
                category=known,
                confidence=100,
                source="memory",
                needs_confirmation=False,
            )
        else:
            miss_indices.append(i)
            miss_lines.append(line)

    if miss_lines:
        raw_response = api_call_fn(vendor, miss_lines, model)
        guesses = _parse_classifier_response(raw_response, expected_count=len(miss_lines))
        for guess in guesses:
            i = miss_indices[guess["index"]]
            results[i] = LineClassification(
                raw_line=miss_lines[guess["index"]],
                category=guess["category"],
                confidence=guess["confidence"],
                source="ai",
                needs_confirmation=True,
            )

    assert all(r is not None for r in results)
    return results  # type: ignore[return-value]


def confirm_classification(
    memory: MemoryStore,
    vendor: str,
    raw_line: str,
    confirmed_category: str,
) -> None:
    """Human confirm/correct step (feeds Phase 5.6's frontend). Persists
    permanently so this exact pattern is never sent to the AI, or
    re-asked of a human, again for this vendor."""
    memory.save_confirmed(vendor, raw_line, confirmed_category)
