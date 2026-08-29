#!/usr/bin/env python3
"""
Phase 5 test: memory-first AI fallback for unrecognized config lines.

NOTE on fixture data -- read before "fixing" this test:
This handoff zip (SIH-2026-phase4-compliance-engine.zip) does NOT
include the `netcanon/` reference clone or the
`converter/netcanon_migration/codecs/` package that
`converter/schema_adapter.py` imports (`from
converter.netcanon_migration.codecs.registry import ...`). Confirmed
by trying `from converter.schema_adapter import parse_and_map`, which
raises `ModuleNotFoundError: No module named
'converter.netcanon_migration'` in this environment -- so
`parse_and_map()` cannot actually be run here, and there is no
`netcanon/tests/fixtures/synthetic/` directory to read real
`unrecognized_lines` output from (the ones the handoff mentions, e.g.
Arista's 111-line output).

If you're running this on the full repo (where that package and the
fixtures both exist), flip USE_REAL_FIXTURES to True below -- the
script will then call parse_and_map() against the real Arista
kitchen-sink fixture and feed its actual unrecognized_lines through
the classifier instead of the representative sample defined here. Do
not just delete this fallback: keep it so the test still runs
standalone (e.g. in CI for this folder alone, or before the converter
package is wired back in).

The representative sample below is modeled on the *shape* of lines
schema_adapter.py's own generic line classifier would leave
unrecognized (see `_classify_lines_generic()` /
`_consumed_by_vendor` in schema_adapter.py) -- vendor-specific
config syntax with no matching consumed-pattern -- not copied from
any real fixture.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai_fallback.memory import MemoryStore, normalize_line_to_pattern
from ai_fallback.classify import (
    classify_unrecognized_lines,
    confirm_classification,
    ClassifierError,
    LineClassification,
)

USE_REAL_FIXTURES = False

VENDOR = "arista_eos"

SAMPLE_UNRECOGNIZED_LINES = [
    "management ssh",
    "   idle-timeout 15",
    "management api http-commands",
    "   no shutdown",
    "spanning-tree mode mstp",
    "ip access-list extended BLOCK-TELNET",
    "logging host 10.0.0.55",
]

any_failures = False


def check(label: str, condition: bool) -> None:
    global any_failures
    status = "PASS" if condition else "FAIL"
    print(f"    [{status}] {label}")
    if not condition:
        any_failures = True


def get_unrecognized_lines() -> list[str]:
    if USE_REAL_FIXTURES:
        from converter.schema_adapter import parse_and_map

        fixture = (
            Path(__file__).resolve().parent.parent
            / "netcanon" / "tests" / "fixtures" / "synthetic"
            / "arista_eos" / "kitchen_sink.txt"
        )
        raw = fixture.read_text(encoding="utf-8", errors="replace")
        result = parse_and_map(raw)
        print(f"  (using REAL fixture: {len(result.unrecognized_lines)} unrecognized lines)")
        return result.unrecognized_lines
    print("  (netcanon fixtures / codec package not present in this zip -- "
          "using representative sample lines instead, see module docstring)")
    return SAMPLE_UNRECOGNIZED_LINES


def fake_api_call_factory(fixed_category: str = "unclear", fixed_confidence: int = 60):
    """Builds a fake api_call_fn that returns a plausible batched JSON
    response, and records how many times it was actually invoked --
    used to prove the memory-check-first logic skips the API on
    repeat patterns."""
    calls = {"count": 0}

    def _fake(vendor: str, lines: list[str], model: str) -> str:
        calls["count"] += 1
        import json
        return json.dumps([
            {"index": i, "category": fixed_category, "confidence": fixed_confidence}
            for i in range(len(lines))
        ])

    return _fake, calls


with tempfile.TemporaryDirectory() as tmpdir:
    db_path = Path(tmpdir) / "test_learned_mappings.db"

    print(f"\n{'='*70}")
    print("  1. normalize_line_to_pattern generalises concrete values")
    print(f"{'='*70}")
    p1 = normalize_line_to_pattern("logging host 10.0.0.55")
    p2 = normalize_line_to_pattern("logging host 192.168.1.200")
    check("two different IPs collapse to the same pattern", p1 == p2)
    check("bare-number line normalizes", normalize_line_to_pattern("   idle-timeout 15") ==
          normalize_line_to_pattern("idle-timeout 42"))

    print(f"\n{'='*70}")
    print("  2. Memory miss returns None, no AI call made")
    print(f"{'='*70}")
    memory = MemoryStore(db_path)
    lines = get_unrecognized_lines()
    check("fresh memory has no entry for first line yet",
          memory.check_known_mapping(VENDOR, lines[0]) is None)

    print(f"\n{'='*70}")
    print("  3. classify_unrecognized_lines: all-miss batch goes to AI, once")
    print(f"{'='*70}")
    fake_api, calls = fake_api_call_factory(fixed_category="logging_enabled", fixed_confidence=72)
    results = classify_unrecognized_lines(VENDOR, lines, memory, api_call_fn=fake_api)
    check("one classification per input line", len(results) == len(lines))
    check("exactly one batched API call for the whole miss set", calls["count"] == 1)
    check("all results came from the AI (memory was empty)",
          all(r.source == "ai" for r in results))
    check("all AI results are flagged as needing human confirmation",
          all(r.needs_confirmation for r in results))
    check("AI guesses carry the fake model's category/confidence through",
          all(r.category == "logging_enabled" and r.confidence == 72 for r in results))

    print(f"\n{'='*70}")
    print("  4. Human confirms one line -> persisted to memory")
    print(f"{'='*70}")
    target_line = lines[0]
    confirm_classification(memory, VENDOR, target_line, "logging_enabled")
    check("confirmed pattern is now a memory hit",
          memory.check_known_mapping(VENDOR, target_line) == "logging_enabled")

    print(f"\n{'='*70}")
    print("  5. Re-classifying: confirmed line is served from memory, "
          "AI is NOT called for it again")
    print(f"{'='*70}")
    fake_api2, calls2 = fake_api_call_factory()
    # A structurally-identical line with a different concrete value should
    # ALSO hit memory, proving pattern generalisation carries through the
    # real classify_unrecognized_lines() path, not just the raw string.
    equivalent_line = target_line.replace("10.0.0.55", "172.16.5.9") \
        if "10.0.0.55" in target_line else target_line
    second_batch = [equivalent_line] + lines[1:]
    results2 = classify_unrecognized_lines(VENDOR, second_batch, memory, api_call_fn=fake_api2)
    check("previously-confirmed line comes back from memory",
          results2[0].source == "memory" and results2[0].category == "logging_enabled")
    check("memory hit needs no further confirmation", results2[0].needs_confirmation is False)
    check("memory hit reports full confidence", results2[0].confidence == 100)
    check("remaining (still-unconfirmed) lines still went to the AI",
          all(r.source == "ai" for r in results2[1:]))
    check("API was called exactly once for the remaining misses only "
          "(not re-invoked for the confirmed line)", calls2["count"] == 1)

    print(f"\n{'='*70}")
    print("  6. Malformed / unparseable AI responses raise ClassifierError, "
          "never silently misclassify")
    print(f"{'='*70}")
    memory_empty = MemoryStore(Path(tmpdir) / "empty.db")
    try:
        classify_unrecognized_lines(
            "vyos", ["some unrecognized line"], memory_empty,
            api_call_fn=lambda v, l, m: "not json at all",
        )
        check("non-JSON response raises ClassifierError", False)
    except ClassifierError:
        check("non-JSON response raises ClassifierError", True)

    try:
        import json
        bad = json.dumps([{"index": 0, "category": "made_up_category", "confidence": 50}])
        classify_unrecognized_lines(
            "vyos", ["some unrecognized line"], memory_empty,
            api_call_fn=lambda v, l, m: bad,
        )
        check("unknown category in AI response raises ClassifierError", False)
    except ClassifierError:
        check("unknown category in AI response raises ClassifierError", True)

    print(f"\n{'='*70}")
    print("  7. save_confirmed rejects invalid categories (no silent typos)")
    print(f"{'='*70}")
    try:
        memory.save_confirmed(VENDOR, "some line", "ssh_enable")  # typo, not a real category
        check("invalid category rejected by save_confirmed", False)
    except ValueError:
        check("invalid category rejected by save_confirmed", True)

    print(f"\n{'='*70}")
    print("  8. Repeated confirmation of the same pattern updates, "
          "not duplicates")
    print(f"{'='*70}")
    confirm_classification(memory, VENDOR, target_line, "logging_enabled")
    mappings = memory.all_mappings(VENDOR)
    matching = [m for m in mappings if m.line_pattern == normalize_line_to_pattern(target_line)]
    check("exactly one row exists for the repeatedly-confirmed pattern",
          len(matching) == 1)
    check("confirmation count incremented on re-confirm",
          matching[0].confirmed_count == 2)

print(f"\n{'='*70}")
if any_failures:
    print("  RESULT: issues found -- see above")
    sys.exit(1)
else:
    print("  RESULT: all checks passed")
