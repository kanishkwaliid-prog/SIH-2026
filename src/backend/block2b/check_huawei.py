from block2b.llm_classifier import classify_unknown_line
import sys

path = path = sys.argv[1]

for line in open(path, encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    r = classify_unknown_line(line)
    print(f"{line[:45]:45} -> {r['field']}={r['value']} ({r['source']})")

from block2b.llm_classifier import guess_vendor
print(guess_vendor(open(path, encoding="utf-8").read()))