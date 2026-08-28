from llm_classifier import classify_unknown_line, guess_vendor, needs_human_review

test_cases = [
    ("aaa new-model", "authentication"),
    ("logging trap informational", "logging"),
    ("crypto key generate rsa", "encryption"),
    ("access-list 101 permit tcp any any eq 22", "access_control"),
    ("line vty 0 4", "session_management"),
    ("exec-timeout 10 0", "session_management"),
    ("ntp server 10.0.0.1", "other"),
    ("username admin secret 5 $1$abcd", "authentication"),
]
test_cases += [
    ("set system login user admin class super-user", "authentication"),   # Juniper
    ("set deviceconfig system timezone US/Pacific", "other"),              # Palo Alto
    ("no logging console", "logging"),
    ("service password-encryption", "encryption"),
    ("ip access-group 101 in", "access_control"),
    ("snmp-server community public RO", "authentication"),
]
correct = 0
for line, expected in test_cases:
    result = classify_unknown_line(line)
    match = result.get("category") == expected
    correct += match
    flag = "⚠ NEEDS REVIEW" if needs_human_review(result) else ""
    print(f"{line[:35]:35} → {result.get('category',''):20} expected={expected:20} {'✓' if match else '✗'} {flag}")

print(f"\nAccuracy: {correct}/{len(test_cases)}")

# quick vendor guess test
sample_config = """
set deviceconfig system hostname fw01
set network interface ethernet1/1 layer3 ip 10.0.0.1/24
"""
print("\nVendor guess:", guess_vendor(sample_config))

def test_retry_on_failure():
    from groq import Groq
    import llm_classifier

    print("\n--- Testing retry/fallback on bad API key ---")
    # Temporarily swap in a broken client
    original_client = llm_classifier.client
    llm_classifier.client = Groq(api_key="invalid_key_on_purpose")

    result = llm_classifier.call_with_retry(
        llm_classifier.classify_unknown_line, "aaa new-model"
    )
    print("Result with broken key:", result)

    assert result.get("category") == "unclassified", "Should fail gracefully, not crash"
    print("✓ Retry/fallback works — no crash on bad key")

    # Restore the real client
    llm_classifier.client = original_client

test_retry_on_failure()

def test_edge_cases():
    from llm_classifier import classify_unknown_line

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
        print(f"Input: {line[:30]!r:35} → {result.get('category')} (conf: {result.get('confidence')})")

test_edge_cases()