"""
Trains the local TF-IDF pre-filter model.

Run from src/backend/:
    python -m block2b.train_prefilter            # picks C by cross-validation
    python -m block2b.train_prefilter --C 10     # force a specific C

What changed vs the old version:
  * No more prefilter_holdout.csv. The old script saved a test split and then
    trained the SAVED model on all rows, including that split, so
    tune_prefilter_threshold.py was scoring lines the model had already seen.
    Honest numbers now come from leave-one-out CV here, and from a set of
    independently labeled REAL lines (see tune_prefilter_threshold.py).
  * C (regularization strength) is chosen by CV instead of sklearn's default
    of 1.0. With TF-IDF rows L2-normalized and ~11 classes, C=1 gives flat
    probabilities (the model was ~0.3 confident even on its own training
    lines), so no confidence threshold could separate right from wrong.
  * Duplicate lines are dropped and conflicting labels are reported.
"""

import argparse
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import LeaveOneOut, StratifiedKFold
from sklearn.pipeline import Pipeline

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "prefilter_training_data.csv")
MODEL_PATH = os.path.join(BASE_DIR, "prefilter_model.joblib")

CANDIDATE_C = [1, 3, 10, 30, 100]
CV_THRESHOLD = 0.70          # keep in sync with prefilter.CONFIDENCE_THRESHOLD
TARGET_PRECISION = 0.95
MIN_COVERAGE = 0.30


def build_pipeline(C=1.0):
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char_wb",   # char n-grams suit config syntax better than word tokens
            ngram_range=(2, 5),
            min_df=1,
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(C=C, max_iter=3000, class_weight="balanced")),
    ])


def load_data():
    df = pd.read_csv(DATA_PATH)
    df["line"] = df["line"].astype(str).str.strip()
    df = df[df["line"] != ""]

    conflicts = df.groupby("line")["label"].nunique()
    conflicts = conflicts[conflicts > 1]
    if len(conflicts):
        print(f"WARNING: {len(conflicts)} line(s) have conflicting labels (keeping the first):")
        for line in conflicts.index:
            print(f"   {line!r}: {sorted(df[df['line'] == line]['label'].unique())}")

    before = len(df)
    df = df.drop_duplicates("line").reset_index(drop=True)
    if len(df) < before:
        print(f"Dropped {before - len(df)} duplicate line(s).")
    return df


def cv_predictions(C, X, y):
    """Out-of-fold (pred, confidence) for every row. LOO for small data."""
    if len(X) <= 400:
        splits = LeaveOneOut().split(X)
    else:
        splits = StratifiedKFold(5, shuffle=True, random_state=42).split(X, y)
    preds = np.empty(len(X), dtype=object)
    conf = np.zeros(len(X))
    for tr, te in splits:
        m = build_pipeline(C).fit(X[tr], y[tr])
        p = m.predict_proba(X[te])
        preds[te] = m.classes_[p.argmax(1)]
        conf[te] = p.max(1)
    return preds, conf


def choose_C(X, y):
    print(f"\n{'C':>5} {'cv_acc':>8} {'cov@'+str(CV_THRESHOLD):>10} {'prec@'+str(CV_THRESHOLD):>10}")
    print("-" * 38)
    best = None
    for C in CANDIDATE_C:
        preds, conf = cv_predictions(C, X, y)
        ok = preds == y
        sel = conf >= CV_THRESHOLD
        cov = sel.mean()
        prec = ok[sel].mean() if sel.any() else 0.0
        print(f"{C:>5} {ok.mean():>8.2f} {cov:>9.0%} {prec:>10.0%}")
        prec_rounded = round(prec,2)
        meets_target = prec_rounded >= TARGET_PRECISION and cov >= MIN_COVERAGE
        score = (meets_target, cov)
        if best is None or score > best[0]:
            best = (score, C)
    return best[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--C", type=float, default=None)
    args = ap.parse_args()

    df = load_data()
    X, y = df["line"].values, df["label"].values
    print(f"Loaded {len(df)} unique lines across {df['label'].nunique()} labels")
    print(df["label"].value_counts(), "\n")

    C = args.C if args.C is not None else choose_C(X, y)
    print(f"\nUsing C={C}")

    final = build_pipeline(C).fit(X, y)
    joblib.dump(final, MODEL_PATH)
    print(f"Saved model -> {MODEL_PATH}")
    print("\nNOTE: CV numbers above are on your own training-style lines. They are")
    print("an upper bound. Judge the model on independently labeled real lines.")


if __name__ == "__main__":
    main()