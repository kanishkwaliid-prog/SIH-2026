"""
Sweeps confidence thresholds against INDEPENDENTLY LABELED real lines.

Do NOT point this at lines from prefilter_training_data.csv: the saved model
is trained on every row of that file, so it would just be graded on its own
training data (this is what the old holdout check was doing).

Input CSV (default block2b/real_eval.csv), columns: line,label
  label uses the same strings as the training data, e.g.
  ssh_enabled:true, password_encryption:type7, unclear
  (fill these in by hand from the `eval` rows of labeling_sheet.csv)

Run from src/backend/:
    python -m block2b.tune_prefilter_threshold
    python -m block2b.tune_prefilter_threshold path\\to\\other_eval.csv

Reports two tables:
  * FULL PIPELINE  = deterministic rules first, then the ML model (what
                     classify_locally() really does in production)
  * ML ONLY        = the TF-IDF model by itself, rules bypassed
so you can see how much of the coverage is the rules and how much is the model.
"""

import os
import sys

import pandas as pd

from block2b.prefilter import _decode_label, _load, classify_locally

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATH = os.path.join(BASE_DIR, "real_eval.csv")
THRESHOLDS = [0.40, 0.50, 0.60, 0.70, 0.80, 0.90]


def _same(field, value, label):
    exp_field, exp_value = _decode_label(label)
    return field == exp_field and value == exp_value


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PATH
    df = pd.read_csv(path)
    df["line"] = df["line"].astype(str).str.strip()
    df = df[(df["line"] != "") & df["label"].notna()].reset_index(drop=True)
    print(f"{len(df)} labeled lines from {path}\n")

    model = _load()
    proba = model.predict_proba(df["line"].tolist())
    ml_conf = proba.max(1)
    ml_label = model.classes_[proba.argmax(1)]

    print("FULL PIPELINE (rules + ML)")
    print(f"{'thresh':>7} {'coverage':>10} {'correct':>10} {'precision':>10}")
    print("-" * 42)
    for t in THRESHOLDS:
        handled = correct = 0
        for _, row in df.iterrows():
            r = classify_locally(row["line"], threshold=t)
            if r is not None:
                handled += 1
                correct += _same(r["field"], r["value"], row["label"])
        prec = correct / handled * 100 if handled else 0.0
        print(f"{t:>7.2f} {handled / len(df) * 100:>9.1f}% {correct:>4}/{handled:<5} {prec:>9.1f}%")

    print("\nML ONLY (rules bypassed)")
    print(f"{'thresh':>7} {'coverage':>10} {'correct':>10} {'precision':>10}")
    print("-" * 42)
    for t in THRESHOLDS:
        sel = ml_conf >= t
        n = int(sel.sum())
        c = sum(ml_label[i] == df["label"][i] for i in range(len(df)) if sel[i])
        prec = c / n * 100 if n else 0.0
        print(f"{t:>7.2f} {n / len(df) * 100:>9.1f}% {c:>4}/{n:<5} {prec:>9.1f}%")

    acc = (ml_label == df["label"].values).mean()
    print(f"\nML argmax accuracy on these lines: {acc:.0%}")
    print("Pick the lowest threshold where precision still holds ~95-100%.")
    print("A wrong local answer is worse than one extra Groq call.")


if __name__ == "__main__":
    main()