"""
block2b/mine_rare_classes.py

You have zero eval examples and almost no training data for two classes:
ssh_enabled:false and logging_enabled:false. That's not a rules problem
or a model problem -- it's a "we've never found enough real examples"
problem. This script fixes that specific gap: it scans sample_configs
with a WIDE net of vendor-specific disable phrasings for just these two
classes (not the whole schema) and dumps candidates to a small CSV for
you to hand-label.

This is deliberately over-inclusive -- it's a recall tool, not a
precision tool. It WILL catch some false positives (lines that mention
ssh/logging but aren't really an on/off toggle). That's fine: you're
about to look at every row anyway, and a handful of "no, that's not it"
rows is a much better problem than "I have 3 examples total."

Run from src/backend/:
    python -m block2b.mine_rare_classes shared\\sample_configs

Output: block2b/rare_class_candidates.csv with columns
    guess, line, source_file, line_no, matched_pattern

`guess` is just this script's best guess at the label (ssh_enabled:false
or logging_enabled:false) -- fill in the real `label` column yourself;
rename/overwrite `guess` -> `label` once you've reviewed each row, same
as the labeling_sheet.csv workflow. Anything you keep, feed through
label_helper.py same as usual (add these lines to labeling_sheet.csv,
or append straight to prefilter_training_data.csv / real_eval.csv).
"""

import argparse
import csv
import re
from pathlib import Path

# Each entry: (label, description, compiled pattern). Order doesn't
# matter here -- unlike the runtime rules, this is a candidate hunt,
# not a classifier, so a line can legitimately match more than one
# pattern and that's fine (dedup by line text at the end).
CANDIDATES = [
    # --- ssh_enabled:false, by vendor ---
    ("ssh_enabled:false", "cisco: no ip ssh / ip ssh disable",
     r"^\s*no\s+ip\s+ssh\b|^\s*ip\s+ssh\s+disable\b"),
    ("ssh_enabled:false", "juniper: delete/deactivate system services ssh",
     r"^\s*(delete|deactivate)\s+system\s+services\s+ssh\b"),
    ("ssh_enabled:false", "fortios: unset/disable ssh admin access",
     r"\bunset\s+allow-service\b.*\bsshd?\b|^\s*set\s+allow-service\s+.*(?<!ssh)\s*$"),
    ("ssh_enabled:false", "routeros: set ssh disabled=yes",
     r"^\s*set\s+ssh\b.*\bdisabled=yes\b"),
    ("ssh_enabled:false", "vyos: delete service ssh",
     r"^\s*delete\s+service\s+ssh\b"),
    ("ssh_enabled:false", "opnsense/pfsense xml: sshd disabled",
     r"<sshd>\s*(<enabled>\s*0\s*</enabled>|</sshd>)|<enabled>\s*0\s*</enabled>\s*</sshd>"),
    ("ssh_enabled:false", "generic: ssh service stopped/disabled phrasing",
     r"\bssh\b.{0,20}\b(disabled|stopped|off|shutdown)\b|\b(disable|stop|shutdown)\b.{0,20}\bssh\b"),
    ("ssh_enabled:false", "aruba/hp: no ip ssh server",
     r"^\s*no\s+ip\s+ssh\s+server\b"),

    # --- logging_enabled:false, by vendor ---
    ("logging_enabled:false", "cisco: no logging on/trap/host",
     r"^\s*no\s+logging\s+(on|trap|host)\b"),
    ("logging_enabled:false", "juniper: delete system syslog",
     r"^\s*(delete|deactivate)\s+system\s+syslog\b"),
    ("logging_enabled:false", "fortios: set status disable under log config",
     r"^\s*set\s+status\s+disable\s*$"),
    ("logging_enabled:false", "routeros: syslog action disabled=yes",
     r"^\s*set\s+\d+\s+.*\bdisabled=yes\b.*\bremote\b|^\s*/system\s+logging\s+.*\bdisabled=yes\b"),
    ("logging_enabled:false", "vyos: delete system syslog",
     r"^\s*delete\s+system\s+syslog\b"),
    ("logging_enabled:false", "opnsense/pfsense xml: syslog disabled",
     r"<syslog>\s*<enable>\s*0\s*</enable>|<enable>\s*0\s*</enable>\s*</syslog>"),
    ("logging_enabled:false", "generic: logging/syslog disabled phrasing",
     r"\b(logging|syslog)\b.{0,20}\b(disabled|stopped|off)\b|\b(disable|stop)\b.{0,20}\b(logging|syslog)\b"),
    ("logging_enabled:false", "cisco: no logging console/buffered (often paired w/ full disable)",
     r"^\s*no\s+logging\s+(buffered|console)\b"),
]

_COMPILED = [(label, desc, re.compile(pat, re.IGNORECASE)) for label, desc, pat in CANDIDATES]

SKIP_PREFIXES = ("!", "#")


def collect(root):
    rows, seen = [], set()
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
            for label, desc, pat in _COMPILED:
                if pat.search(line):
                    key = (line.lower(), label)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append((label, line, p.name, n, desc))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("configs_dir")
    ap.add_argument("--out", default="block2b/rare_class_candidates.csv")
    args = ap.parse_args()

    rows = collect(args.configs_dir)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["guess", "line", "source_file", "line_no", "matched_pattern"])
        for label, line, src, n, desc in sorted(rows, key=lambda r: r[0]):
            w.writerow([label, line, src, n, desc])

    by_label = {}
    for label, *_ in rows:
        by_label[label] = by_label.get(label, 0) + 1

    print(f"{len(rows)} candidate lines -> {out}")
    for label, count in sorted(by_label.items()):
        print(f"  {label:30} {count}")
    if not rows:
        print("\nNo candidates found. Either sample_configs genuinely has no "
              "disable-style lines for these classes, or the vendor phrasing "
              "used doesn't match any pattern here -- worth eyeballing a few "
              "files by hand to check before concluding the data isn't there.")
    print("\nReview every row: this net is intentionally wide, so 'guess' "
          "will be wrong sometimes. Fix/confirm the label, then fold the "
          "keepers into labeling_sheet.csv (or straight into "
          "prefilter_training_data.csv / real_eval.csv) via the usual "
          "label_helper.py workflow.")


if __name__ == "__main__":
    main()
