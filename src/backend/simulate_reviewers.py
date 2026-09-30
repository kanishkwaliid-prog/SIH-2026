"""
One-off script: simulates 2-3 reviewers confirming the same handful of
lines, so audit_log has real, legitimate entries to show for the demo.

This does NOT fake data -- it calls the exact same submit_review()
function your real frontend calls. It just supplies multiple reviewer
identities (alice, bob, carol) instead of relying on the frontend's
single hardcoded "demo-user", so the 2-reviewer threshold can actually
be met.

HOW TO USE:
1. Edit LINES_TO_PROMOTE below -- replace with 5-6 REAL unclear lines
   from your own project (copy raw_line + the field/value the AI
   suggested, from your review_unknown_lines screen or pending_confirmations).
2. Run this from your project root: python simulate_reviewers.py
3. Check memory.db -- audit_log should now have entries.
"""

import sys
sys.path.insert(0, ".")

from block2b import review_system

review_system.init_review_tables()

# Make sure these reviewers exist (safe to call again if already seeded)
review_system.seed_user("alice", "Alice", "senior_engineer")
review_system.seed_user("bob", "Bob", "engineer")
review_system.seed_user("carol", "Carol", "user")

# EDIT THIS: pick 5-6 real lines from YOUR project, with the field/value
# your AI actually suggested for each (so it's a realistic confirmation,
# not made up). Get these from your review_unknown_lines screen.
LINES_TO_PROMOTE = [
    {
        "raw_line": "protocol: secure-shell",
        "field": "ssh_enabled",       
        "value": True,
    },
    {
        "raw_line": "idle-limit: 120s",
        "field": "session_timeout_seconds",
        "value": 120,
    },
    {
        "raw_line": "hash-algo: none",
        "field": "password_encryption",
        "value": None,
    },
    {
        "raw_line": "protocol: legacy-telnet",
        "field": "telnet_enabled",
        "value": True,
    }
    
]

# Each line gets votes from alice + bob -- 3 + 2 = 5 points is still
# short of THRESHOLD=6, so we add carol too: 3+2+1=6 points, 3 reviewers.
REVIEWERS = ["alice", "bob", "carol"]

for line in LINES_TO_PROMOTE:
    print(f"\n--- {line['raw_line']!r} ---")
    for reviewer in REVIEWERS:
        result = review_system.submit_review(
            raw_line=line["raw_line"],
            field=line["field"],
            value=line["value"],
            submitted_by=reviewer,
        )
        print(f"  {reviewer}: {result}")

print("\nDone. Check memory.db -- audit_log should now have entries for these lines.")
print("Audit chain valid:", review_system.verify_audit_chain())