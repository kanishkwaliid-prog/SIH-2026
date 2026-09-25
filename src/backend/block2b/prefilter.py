"""
Block 2b - Local TF-IDF pre-filter.

Sits in front of the Groq LLM call inside classify_unknown_line(). Its
only job is to catch config lines that are "obviously" one of the known
NormalizedConfig fields, without spending an API call on them.

Scope cuts (deliberate, not gaps):
  - session_timeout_seconds is NEVER predicted locally. Extracting the
    actual integer ("exec-timeout 10 0" -> 600) is parsing, not
    classification, and belongs to the LLM/regex layer, not this model.
    Any line that looks timeout-related is routed straight to Groq.
  - Labels are combined "field:value" strings (e.g. "ssh_enabled:true"),
    not separate field/value predictions -- simpler model, and it
    naturally handles lines where field and value are entangled
    (e.g. "transport input telnet ssh" -> telnet_enabled:true).

Output shape matches llm_classifier.classify_unknown_line()'s return
value exactly, so callers can't tell the difference except by "source".
"""

import os
import re
import joblib
from block2b.rules_prefilter import rule_labels

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "prefilter_model.joblib")

CONFIDENCE_THRESHOLD = 0.70  # tune with tune_prefilter_threshold.py

# Lines matching this are ALWAYS sent to Groq, never guessed locally --
# session_timeout_seconds needs real arithmetic, which this model doesn't do.
_TIMEOUT_PATTERN = re.compile(r"\b(exec-timeout|session[-_ ]?timeout|idle-timeout)\b", re.IGNORECASE)

_model = None


def _load():
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Pre-filter model not found at {MODEL_PATH}. "
                f"Run: python -m block2b.train_prefilter"
            )
        _model = joblib.load(MODEL_PATH)
    return _model


def is_model_available() -> bool:
    return os.path.exists(MODEL_PATH)


def _decode_label(label: str):
    """'ssh_enabled:true' -> ('ssh_enabled', True). 'unclear' -> ('unclear', None)."""
    if label == "unclear":
        return "unclear", None
    field, _, raw_value = label.partition(":")
    if raw_value == "true":
        value = True
    elif raw_value == "false":
        value = False
    else:
        value = raw_value  # password_encryption: "type7" / "type5" / "none"
    return field, value


def classify_locally(raw_line: str, threshold: float = CONFIDENCE_THRESHOLD):
    """
    Returns a dict in the same shape as classify_unknown_line(), or None
    if this line should be deferred to Groq (low confidence, timeout
    line, empty model, etc.)
    """
    text = (raw_line or "").strip()
    if not text:
        return None

    if _TIMEOUT_PATTERN.search(text):
        return None  # always defer -- see module docstring

    # Deterministic rules run first -- free, zero-training-data wins.
    # Only trust a rule match when exactly one label fired: 0 labels means
    # no rule recognized this line (fall through to the ML model below);
    # 2+ labels means a genuinely multi-field line (e.g. "transport input
    # ssh telnet" sets BOTH ssh_enabled and telnet_enabled), which this
    # single field/value return shape can't represent -- defer those to
    # the LLM rather than silently reporting only one of the two fields.
    rule_hits = rule_labels(text)
    if len(rule_hits) == 1:
        field, value = _decode_label(next(iter(rule_hits)))
        return {
            "field": field,
            "value": value,
            "confidence": 1.0,
            "reasoning": "Matched by deterministic rule",
            "source": "local_rules",
        }

    if not is_model_available():
        return None

    model = _load()
    proba = model.predict_proba([text])[0]
    idx = proba.argmax()
    label = model.classes_[idx]
    confidence = float(proba[idx])

    if confidence < threshold:
        return None

    field, value = _decode_label(label)
    return {
        "field": field,
        "value": value,
        "confidence": round(confidence, 4),
        "reasoning": "Matched by local TF-IDF pre-filter",
        "source": "local_prefilter",
    }