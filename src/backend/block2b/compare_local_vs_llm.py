"""
block2b/compare_local_vs_llm.py

Runs the SAME labeled lines through (a) the local layer (rules + TF-IDF,
classify_locally) and (b) Groq alone (bypassing memory, cache and prefilter),
then reports accuracy of each and lists every disagreement.

Save as src/backend/block2b/compare_local_vs_llm.py and run from src/backend/:
    python -m block2b.compare_local_vs_llm --n-unclear 150

Uses Groq calls: (all real settings + local mistakes + --n-unclear random
unclear lines). Default ~ 114 + ~29 + 150 = ~300 calls. Use --limit to cap.
Results are written line by line to block2b/compare_results.csv, so an
interrupted run (rate limit / daily quota) still leaves usable data.
DO NOT commit compare_results.csv.
"""
import argparse
import csv
import os
import random
import sys
import time

import pandas as pd

from block2b.prefilter import classify_locally
from block2b.llm_classifier import _classify_unknown_line_inner

BASE = os.path.dirname(os.path.abspath(__file__))


def to_label(field, value):
    if field in (None, "", "unclear") or value is None:
        return "unclear"
    return f"{field}:{str(value).lower()}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", default=os.path.join(BASE, "real_eval.csv"))
    ap.add_argument("--out", default=os.path.join(BASE, "compare_results.csv"))
    ap.add_argument("--n-unclear", type=int, default=150)
    ap.add_argument("--threshold", type=float, default=0.70)
    ap.add_argument("--limit", type=int, default=0, help="max Groq calls (0 = no cap)")
    ap.add_argument("--sleep", type=float, default=0.6)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    df = pd.read_csv(a.eval, keep_default_na=False)
    df["line"] = df["line"].astype(str).str.strip()
    df = df[df["line"] != ""].reset_index(drop=True)

    # local answers for every line (cheap)
    loc = {}
    for line in df["line"]:
        r = classify_locally(line, threshold=a.threshold)
        loc[line] = r

    def local_label(line):
        r = loc[line]
        return "DEFERRED" if r is None else to_label(r["field"], r["value"])

    real = df[df["label"] != "unclear"]
    local_wrong_unclear = df[(df["label"] == "unclear") &
                             df["line"].map(lambda l: local_label(l) not in ("unclear", "DEFERRED"))]
    rest = df[(df["label"] == "unclear") & ~df["line"].isin(local_wrong_unclear["line"])]
    sample = rest.sample(min(a.n_unclear, len(rest)), random_state=a.seed)
    work = pd.concat([real, local_wrong_unclear, sample]).drop_duplicates("line")
    if a.limit:
        work = work.head(a.limit)
    print(f"Comparing {len(work)} lines "
          f"({len(real)} real settings, {len(local_wrong_unclear)} local false alarms, "
          f"{len(sample)} random unclear)\n")

    rows = []
    with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["line", "truth", "local", "local_conf", "llm", "llm_conf", "llm_reasoning"])
        for i, (line, truth) in enumerate(zip(work["line"], work["label"]), 1):
            lo = local_label(line)
            lconf = "" if loc[line] is None else loc[line]["confidence"]
            try:
                r = _classify_unknown_line_inner(line)
                llm = to_label(r.get("field"), r.get("value"))
                conf, why = r.get("confidence", ""), r.get("reasoning", "")
            except Exception as e:  # rate limit, auth, malformed JSON...
                llm, conf, why = "ERROR", "", f"{type(e).__name__}: {str(e)[:120]}"
                if "tokens per day" in str(e):
                    print("Groq daily quota hit -- stopping. Partial results saved.")
                    break
            w.writerow([line, truth, lo, lconf, llm, conf, why])
            f.flush()
            rows.append((line, truth, lo, llm))
            if i % 25 == 0:
                print(f"  ...{i}/{len(work)}")
            time.sleep(a.sleep)

    n = len(rows)
    if not n:
        sys.exit("No results.")
    llm_ok = sum(l == t for _, t, _, l in rows)
    llm_err = sum(l == "ERROR" for _, _, _, l in rows)
    handled = [(li, t, lo, l) for li, t, lo, l in rows if lo != "DEFERRED"]
    loc_ok = sum(lo == t for _, t, lo, _ in handled)
    agree = sum(lo == l for _, _, lo, l in handled)
    real_rows = [r for r in rows if r[1] != "unclear"]

    print(f"\nLines compared: {n}   Groq errors: {llm_err}")
    print(f"LOCAL: handled {len(handled)}/{n}, correct {loc_ok}/{len(handled)}")
    print(f"GROQ : correct {llm_ok}/{n} ({100*llm_ok/n:.1f}%)")
    if real_rows:
        print(f"Real settings only ({len(real_rows)}): local correct "
              f"{sum(lo == t for _, t, lo, _ in real_rows)}, "
              f"Groq correct {sum(l == t for _, t, _, l in real_rows)}")
    print(f"Local and Groq agree on {agree}/{len(handled)} locally handled lines\n")

    print("=== DISAGREEMENTS (local != Groq) -- each is a rule bug, label bug or prompt bug ===")
    for line, truth, lo, llm in rows:
        if lo != "DEFERRED" and lo != llm:
            who = "local right" if lo == truth else ("Groq right" if llm == truth else "both wrong")
            print(f"  [{who:11}] truth={truth} local={lo} groq={llm} | {line[:70]}")
    print(f"\nFull results: {a.out}  (do not commit)")


if __name__ == "__main__":
    main()
