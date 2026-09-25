"""Build a hand-labeling sheet from real sample configs.

Save as block2b/build_labeling_sheet.py, then run from backend/:
    python -m block2b.build_labeling_sheet shared\\sample_configs

Output: block2b/labeling_sheet.csv with columns
    split, label, model_guess, confidence, line, source_file, line_no

Workflow:
  1. Open the CSV, fill in the `label` column by hand for every row.
  2. Append the rows where split == "train" to prefilter_training_data.csv
     (match that file's column names / label values).
  3. Do NOT train on split == "eval". Those rows are your independent test
     set: evaluate the retrained model on them, so the numbers actually mean
     something on real configs.

ASSUMPTION: prefilter_model.joblib is an sklearn Pipeline (vectorizer +
classifier) that accepts raw strings and supports predict_proba. If it is
something else, adjust the two lines marked ADJUST below.
"""
import argparse
import csv
import random
from pathlib import Path

import joblib

SKIP = {"!", "#", "{", "}", "end", "exit", "quit"}


def collect(root):
    seen, rows = set(), []
    for p in sorted(Path(root).rglob("*")):
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for n, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            key = line.lower()
            if len(line) < 4 or key in SKIP or key in seen:
                continue
            seen.add(key)
            rows.append((line, p.name, n))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("configs_dir")
    ap.add_argument("--model", default="block2b/prefilter_model.joblib")
    ap.add_argument("--out", default="block2b/labeling_sheet.csv")
    ap.add_argument("--eval-frac", type=float, default=0.3)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rows = collect(args.configs_dir)
    if not rows:
        raise SystemExit(f"No usable lines found under {args.configs_dir}")

    model = joblib.load(args.model)
    lines = [r[0] for r in rows]
    proba = model.predict_proba(lines)          # ADJUST if not a Pipeline
    classes = list(model.classes_)              # ADJUST if not a Pipeline

    order = list(range(len(rows)))
    random.Random(args.seed).shuffle(order)
    n_eval = int(len(order) * args.eval_frac)
    eval_idx = set(order[:n_eval])

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["split", "label", "model_guess", "confidence",
                    "line", "source_file", "line_no"])
        # lowest-confidence first so the most informative lines come up top
        for i in sorted(range(len(rows)), key=lambda i: max(proba[i])):
            line, src, n = rows[i]
            j = int(proba[i].argmax())
            w.writerow(["eval" if i in eval_idx else "train", "",
                        classes[j], f"{proba[i][j]:.2f}", line, src, n])

    print(f"{len(rows)} unique lines -> {out}")
    print(f"  train: {len(rows) - n_eval}   eval (keep out of training): {n_eval}")


if __name__ == "__main__":
    main()
