"""
block2b/diagnose_prefilter_gap.py

Diagnoses the gap between tune_prefilter_threshold.py's holdout numbers
(30% coverage, 100% precision) and batch_check.py's real-world numbers
(0% local_prefilter hits on shared/sample_configs).

Runs the trained model at threshold=0.0 (so nothing gets filtered out)
against real lines from sample_configs, and prints the raw confidence
the model assigned to each one. This shows whether the model is just
barely missing the 0.70 cutoff (fixable by lowering the threshold) or
is genuinely lost on this phrasing (needs more/better training data).

Run from src/backend/:
    python -m block2b.diagnose_prefilter_gap shared/sample_configs
"""

import sys
import glob
import os
from block2b.prefilter import _load, _decode_label, is_model_available


def load_lines(folder):
    lines = []
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
        print("Usage: python -m block2b.diagnose_prefilter_gap path/to/sample_configs")
        sys.exit(1)

    if not is_model_available():
        print("No trained model found. Run: python -m block2b.train_prefilter")
        sys.exit(1)

    folder = sys.argv[1]
    lines = load_lines(folder)
    print(f"Loaded {len(lines)} lines from {folder}\n")

    model = _load()

    results = []
    for line, fname in lines:
        proba = model.predict_proba([line])[0]
        idx = proba.argmax()
        label = model.classes_[idx]
        confidence = float(proba[idx])
        field, value = _decode_label(label)
        results.append((confidence, fname, line, field, value))

    # Sort highest confidence first -- these are the model's best guesses
    # on real data, so if even these are low, that's the clearest signal.
    results.sort(key=lambda r: r[0], reverse=True)

    print(f"{'conf':>6}  {'file':30}  {'predicted':25}  line")
    print("-" * 100)
    for confidence, fname, line, field, value in results:
        pred = f"{field}:{value}"
        print(f"{confidence:>6.3f}  {fname:30.30}  {pred:25.25}  {line[:50]}")

    # Summary buckets
    above_70 = sum(1 for r in results if r[0] >= 0.70)
    between_50_70 = sum(1 for r in results if 0.50 <= r[0] < 0.70)
    below_50 = sum(1 for r in results if r[0] < 0.50)

    print(f"\n=== Confidence distribution on real sample_configs lines ===")
    print(f"  >= 0.70 (would pass current threshold): {above_70}")
    print(f"  0.50 - 0.70 (close, threshold-fixable):   {between_50_70}")
    print(f"  < 0.50 (genuinely unsure):                {below_50}")


if __name__ == "__main__":
    main()
