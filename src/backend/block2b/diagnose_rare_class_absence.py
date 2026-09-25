"""
block2b/diagnose_rare_class_absence.py

mine_rare_classes.py found ~0 candidates for ssh_enabled:false /
logging_enabled:false. Before assuming the regexes are wrong, check
whether the underlying content even exists in your corpus. This
script does the loosest possible pass: it just finds every line that
mentions "ssh" or "logging"/"syslog" at all, with zero opinion about
what it means, so you can eyeball actual phrasing instead of guessing
at more regexes blind.

Run from src/backend/:
    python -m block2b.diagnose_rare_class_absence shared\\sample_configs

Output: prints two things to the terminal (no file, this is a quick
look, not a labeling step):
  1. Total line counts mentioning ssh / logging+syslog at all.
  2. Every one of those lines that ALSO contains a generic "off-ness"
     word nearby (disable, off, no, delete, deactivate, stop, false,
     0, none) -- printed in full so you can read the real phrasing
     your corpus actually uses.

If part 1 is near-zero: your sample_configs genuinely doesn't have
much ssh/logging content at all (a corpus-coverage problem, not a
regex problem -- you may need more/different sample configs, not
better patterns).

If part 1 is healthy but part 2 is empty or all irrelevant: the
"off" phrasing in your corpus doesn't look like any of the vendor
patterns anyone's guessed at so far. Read part 2's output and hand
me the phrasing you see -- that's exact material for new rules,
vs. guessing at more vendor syntax blind.
"""

import argparse
import re
from pathlib import Path

SSH_WORD = re.compile(r"\bssh\b", re.IGNORECASE)
LOG_WORD = re.compile(r"\b(logging|syslog)\b", re.IGNORECASE)
OFF_WORD = re.compile(
    r"\b(disable[ds]?|deactivate[d]?|delete[d]?|off|stop(ped)?|false|none|no)\b",
    re.IGNORECASE,
)
SKIP_PREFIXES = ("!", "#")


def collect(root):
    ssh_lines, log_lines = [], []
    for p in sorted(Path(root).rglob("*")):
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for n, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith(SKIP_PREFIXES):
                continue
            if SSH_WORD.search(line):
                ssh_lines.append((line, p.name, n))
            if LOG_WORD.search(line):
                log_lines.append((line, p.name, n))
    return ssh_lines, log_lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("configs_dir")
    args = ap.parse_args()

    ssh_lines, log_lines = collect(args.configs_dir)

    print(f"=== Raw keyword counts (zero filtering beyond the word itself) ===")
    print(f"  lines mentioning 'ssh':             {len(ssh_lines)}")
    print(f"  lines mentioning 'logging'/'syslog': {len(log_lines)}")

    ssh_off = [t for t in ssh_lines if OFF_WORD.search(t[0])]
    log_off = [t for t in log_lines if OFF_WORD.search(t[0])]

    print(f"\n  ...of those, containing an 'off-ness' word too:")
    print(f"  ssh:     {len(ssh_off)}")
    print(f"  logging: {len(log_off)}")

    print(f"\n=== ssh lines with an 'off-ness' word (read these for real phrasing) ===")
    for line, src, n in ssh_off[:80]:
        print(f"  [{src}:{n}] {line}")
    if not ssh_off:
        print("  (none)")

    print(f"\n=== logging/syslog lines with an 'off-ness' word ===")
    for line, src, n in log_off[:80]:
        print(f"  [{src}:{n}] {line}")
    if not log_off:
        print("  (none)")

    print(f"\n=== Sample of ssh lines with NO off-ness word (just to see what IS there) ===")
    ssh_on = [t for t in ssh_lines if t not in ssh_off]
    for line, src, n in ssh_on[:15]:
        print(f"  [{src}:{n}] {line}")


if __name__ == "__main__":
    main()
