"""
block2b/batch_check.py

Runs every line from your real sample_configs files through the full
classify_unknown_line() pipeline (memory -> local pre-filter -> Groq)
and prints what each one resolved to, so you can eyeball results
against configs you actually have -- not just the 17 hand-picked
test cases.

This is NOT a pass/fail test (no "expected" labels) -- it's a scan
for anything that looks wrong, plus a source-breakdown so you can see
how much the local pre-filter is actually catching vs. how much still
goes to Groq.

Run from src/backend/:
    python block2b/batch_check.py path/to/sample_configs
"""

import sys
import glob
import os
from collections import Counter
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from block2b.llm_classifier import classify_unknown_line



def load_lines(folder):
    lines = []
    # picks up .cfg/.conf/.txt/.ios/.junos/etc -- anything text-like
    for path in glob.glob(os.path.join(folder, "**", "*"), recursive=True):
        if os.path.isfile(path):
            try:
                with open(path, "r", errors="ignore") as f:
                    for raw in f:
                        s = raw.strip()
                        if s and not s.startswith(("!", "#")):
                            lines.append((s, os.path.basename(path)))
            except Exception:
                continue
    return lines


def main():
    if len(sys.argv) < 2:
        print("Usage: python block2b/batch_check.py path/to/sample_configs")
        sys.exit(1)

    folder = sys.argv[1]
    lines = load_lines(folder)
    print(f"Loaded {len(lines)} lines from {folder}\n")

    source_counts = Counter()
    field_counts = Counter()
    flagged = []  # low-confidence or unclear-but-suspicious lines

    for line, fname in lines:
        result = classify_unknown_line(line)
        time.sleep(0.5)
        field = result.get("field", "unclear")
        source = result.get("source", "?")
        conf = result.get("confidence", 0.0)

        source_counts[source] += 1
        field_counts[field] += 1

        # Flag things worth a human look: low confidence, or "unclear"
        # on a line that mentions our keywords (possible miss)
        keyword_hit = any(k in line.lower() for k in
                           ["ssh", "telnet", "logging", "banner", "password", "secret", "timeout"])
        if conf < 0.6 or (field == "unclear" and keyword_hit):
            flagged.append((fname, line, field, conf, source))

    print("=== Source breakdown (how much stayed local vs went to Groq) ===")
    for src, count in source_counts.most_common():
        pct = count / len(lines) * 100
        print(f"  {src:20} {count:5}  ({pct:.1f}%)")

    print("\n=== Field breakdown ===")
    for field, count in field_counts.most_common():
        print(f"  {field:30} {count:5}")

    print(f"\n=== Flagged for review: {len(flagged)} lines ===")
    print("(low confidence, or 'unclear' on a line containing a keyword we care about)\n")
    for fname, line, field, conf, source in flagged[:50]:  # cap printed output
        print(f"[{fname}] {line[:60]:60} -> {field} (conf={conf:.2f}, {source})")

    if len(flagged) > 50:
        print(f"... and {len(flagged) - 50} more (see full run for all)")


if __name__ == "__main__":
    main()
