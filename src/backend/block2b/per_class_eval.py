"""
block2b/per_class_eval.py

tune_prefilter_threshold.py reports one aggregate precision number across
all labels. With 'unclear' now ~90% of the data, that number is dominated
by the easy majority class and can look great even if the rare classes
(ssh_enabled:false, telnet_enabled:false, logging_enabled:false -- the
security-relevant "something got turned OFF" lines) are being predicted
wrong. This breaks accuracy down PER LABEL so you can see those specific
classes in isolation.

Run from src/backend/:
    python -m block2b.per_class_eval
    python -m block2b.per_class_eval path\\to\\other_eval.csv
    python -m block2b.per_class_eval --threshold 0.5
"""

import argparse
import os

import pandas as pd

from block2b.prefilter import _decode_label, classify_locally

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATH = os.path.join(BASE_DIR, "real_eval.csv")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=DEFAULT_PATH)
    ap.add_argument("--threshold", type=float, default=0.70)
    args = ap.parse_args()

    df = pd.read_csv(args.path)
    df["line"] = df["line"].astype(str).str.strip()
    df = df[(df["line"] != "") & df["label"].notna()].reset_index(drop=True)
    print(f"{len(df)} labeled lines from {args.path}  (threshold={args.threshold})\n")

    # Per-row: did classify_locally handle it, and was it right?
    handled, correct, pred_label = [], [], []
    for _, row in df.iterrows():
        r = classify_locally(row["line"], threshold=args.threshold)
        if r is None:
            handled.append(False)
            correct.append(False)
            pred_label.append(None)
        else:
            exp_field, exp_value = _decode_label(row["label"])
            ok = r["field"] == exp_field and r["value"] == exp_value
            handled.append(True)
            correct.append(ok)
            pl = "unclear" if r["field"] == "unclear" else f'{r["field"]}:{str(r["value"]).lower()}'
            pred_label.append(pl)

    df["handled"] = handled
    df["correct"] = correct
    df["pred_label"] = pred_label

    print(f"{'true label':30} {'n':>5} {'coverage':>10} {'correct':>10} {'precision':>10}")
    print("-" * 70)
    for label, g in df.groupby("label"):
        n = len(g)
        cov = g["handled"].sum()
        cor = g["correct"].sum()
        prec = cor / cov * 100 if cov else 0.0
        flag = "  <-- rare class" if n <= 10 and label != "unclear" else ""
        print(f"{label:30} {n:>5} {cov / n * 100:>9.1f}% {cor:>4}/{cov:<5} {prec:>9.1f}%{flag}")

    print("\n=== Misclassifications on RARE (non-unclear) classes only ===")
    rare_wrong = df[(df["label"] != "unclear") & (df["handled"]) & (~df["correct"])]
    if rare_wrong.empty:
        print("None -- every handled prediction on a non-unclear class was correct.")
    else:
        for _, row in rare_wrong.iterrows():
            print(f"  true={row['label']:28} pred={row['pred_label']:28} line={row['line'][:60]}")

    print("\n=== Non-unclear rows the model deferred (handled=False) ===")
    rare_deferred = df[(df["label"] != "unclear") & (~df["handled"])]
    if rare_deferred.empty:
        print("None -- every non-unclear line got a local prediction at this threshold.")
    else:
        for _, row in rare_deferred.iterrows():
            print(f"  true={row['label']:28} line={row['line'][:60]}")


if __name__ == "__main__":
    main()
