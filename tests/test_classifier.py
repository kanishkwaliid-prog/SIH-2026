import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from block2b.llm_classifier import classify_unknown_line, guess_vendor, needs_human_review

# Each case: (raw_line, expected_field, expected_value)
# expected_value is checked loosely for session_timeout_seconds (LLM arithmetic
# can be off by small amounts) and exactly for bool/string fields.
test_cases = [
    ("aaa new-model", "unclear", None),
    ("logging trap informational", "logging_enabled", True),
    ("crypto key generate rsa", "unclear", None),          # generates a key, doesn't itself enable SSH
    ("access-list 101 permit tcp any any eq 22", "unclear", None),
    ("line vty 0 4", "unclear", None),
    ("exec-timeout 10 0", "session_timeout_seconds", 600),
    ("ntp server 10.0.0.1", "unclear", None),
    ("username admin secret 5 $1$abcd", "password_encryption", "type5"),  # "secret 5" = MD5 (type 5) hash
]
test_cases += [
    ("set system login user admin class super-user", "unclear", None),   # Juniper
    ("set deviceconfig system timezone US/Pacific", "unclear", None),     # Palo Alto
    ("no logging console", "unclear", None),  # disables console output only, not logging overall -- ambiguous by design
    ("no logging on", "logging_enabled", False),  # this one unambiguously disables all logging
    ("service password-encryption", "password_encryption", "type7"),
    ("ip access-group 101 in", "unclear", None),
    ("transport input ssh", "ssh_enabled", True),
    ("transport input telnet", "telnet_enabled", True),
    ("banner motd ^Authorized access only^", "banner_configured", True),
]

def _value_matches(actual, expected):
    if expected is None:
        return actual is None
    if isinstance(expected, int) and not isinstance(expected, bool):
        # allow small LLM arithmetic slack on timeout conversion
        return actual is not None and abs(actual - expected) <= 5
    return actual == expected

correct = 0
for line, expected_field, expected_value in test_cases:
    result = classify_unknown_line(line)
    field_match = result.get("field") == expected_field
    value_match = _value_matches(result.get("value"), expected_value)
    match = field_match and value_match
    correct += match
    flag = "⚠ NEEDS REVIEW" if needs_human_review(result) else ""
    print(f"{line[:35]:35} → field={result.get('field',''):22} value={str(result.get('value')):8} "
          f"expected=({expected_field}, {expected_value}) {'✓' if match else '✗'} {flag}")

print(f"\nAccuracy: {correct}/{len(test_cases)}")

# quick vendor guess test
sample_config = """
set deviceconfig system hostname fw01
set network interface ethernet1/1 layer3 ip 10.0.0.1/24
"""
print("\nVendor guess:", guess_vendor(sample_config))


def test_retry_on_failure():
    from groq import Groq
    import block2b.llm_classifier as llm_classifier

    print("\n--- Testing retry/fallback on bad API key ---")
    # Temporarily swap in a broken client
    original_client = llm_classifier.client
    llm_classifier.client = Groq(api_key="invalid_key_on_purpose")

    # classify_unknown_line already wraps call_with_retry internally now,
    # so we call it directly -- wrapping it again here would retry-on-retries.
    result = llm_classifier.classify_unknown_line("aaa new-model")
    print("Result with broken key:", result)

    assert result.get("field") == "unclear", "Should fail gracefully, not crash"
    assert result.get("value") is None, "Fallback value should be None"
    print("✓ Retry/fallback works — no crash on bad key")

    # Restore the real client
    llm_classifier.client = original_client


test_retry_on_failure()


def test_vendor_retry_on_failure():
    """Same as above but for guess_vendor, which uses a different fallback shape."""
    from groq import Groq
    import block2b.llm_classifier as llm_classifier

    print("\n--- Testing vendor retry/fallback on bad API key ---")
    original_client = llm_classifier.client
    llm_classifier.client = Groq(api_key="invalid_key_on_purpose")

    result = llm_classifier.guess_vendor("hostname fw01\nset network interface eth1")
    print("Result with broken key:", result)

    assert result.get("vendor") == "Unknown", "Should fail gracefully with vendor fallback shape"
    print("✓ Vendor retry/fallback works — correct fallback shape, no crash")

    llm_classifier.client = original_client


test_vendor_retry_on_failure()


def test_edge_cases():
    from block2b.llm_classifier import classify_unknown_line

    print("\n--- Testing edge cases ---")
    edge_cases = [
        "",                                    # empty line
        "   ",                                 # whitespace only
        "!!!@#$%^&*()_+ garbled nonsense !!!",  # gibberish
        "a" * 500,                              # very long line
        "# just a comment line",                # comment, not a real config line
    ]

    for line in edge_cases:
        result = classify_unknown_line(line)
        print(f"Input: {line[:30]!r:35} → {result.get('field')}={result.get('value')} (conf: {result.get('confidence')})")


test_edge_cases()