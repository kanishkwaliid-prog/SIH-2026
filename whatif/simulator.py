"""
whatif.simulator
------------------
Phase 6 -- lets a user hypothetically edit fields of an already-parsed
``NormalizedConfig`` and see the projected effect on compliance
findings and risk score, WITHOUT touching the real stored config.

Reuses ``compliance_engine.evaluate.evaluate_config`` and
``.risk_score`` rather than re-deriving evaluation logic -- this module
is only responsible for (a) building a scratch copy with the proposed
overrides and (b) diffing before/after.
"""

from __future__ import annotations

import dataclasses
from typing import Any


class SimulationError(ValueError):
    """Raised when overrides can't be applied to the config (e.g. an
    unknown field name, or a config type this module doesn't know how
    to safely copy)."""


def _with_overrides(config: Any, overrides: dict) -> Any:
    """Returns a NEW config object with ``overrides`` applied, never
    mutating ``config`` itself. Supports pydantic v2 (``model_copy``),
    pydantic v1 (``copy``), and plain dataclasses -- whichever
    ``NormalizedConfig`` turns out to be in the real repo.
    """
    if not overrides:
        # Still return a distinct copy so callers can never accidentally
        # hang on to a reference to the original and mutate it later.
        overrides = {}

    unknown = [k for k in overrides if not hasattr(config, k)]
    if unknown:
        raise SimulationError(
            f"Unknown NormalizedConfig field(s) in overrides: {unknown}"
        )

    if hasattr(config, "model_copy"):          # pydantic v2
        return config.model_copy(update=overrides)
    if hasattr(config, "copy") and hasattr(config, "model_fields"):  # pydantic v1/v2 BaseModel.copy
        return config.copy(update=overrides)
    if dataclasses.is_dataclass(config):
        return dataclasses.replace(config, **overrides)
    raise SimulationError(
        f"Don't know how to safely copy config of type {type(config).__name__} "
        "(expected a pydantic model or a dataclass)"
    )


def _findings_by_rule_id(findings) -> dict:
    return {f.rule_id: f for f in findings}


def simulate_change(
    base_config,
    overrides: dict,
    vendor: str,
    rule_pack: dict,
    cross_reference_pack: dict | None = None,
) -> dict:
    """Evaluates ``base_config`` as-is, then again with ``overrides``
    applied to a scratch copy, and returns:

        {
          "before_score": float,
          "after_score": float,
          "findings_diff": [
              {"rule_id": ..., "before_status": ..., "after_status": ...},
              ...  # only rules whose status actually flipped
          ],
        }

    ``base_config`` is never mutated -- overrides are applied to a
    fresh copy via ``_with_overrides``.
    """
    # Imported lazily so this module has no hard import-time dependency
    # on compliance_engine being on the path in isolated tests.
    from compliance_engine.evaluate import evaluate_config, risk_score

    baseline_findings = evaluate_config(base_config, vendor, rule_pack, cross_reference_pack)
    scratch_config = _with_overrides(base_config, overrides)
    projected_findings = evaluate_config(scratch_config, vendor, rule_pack, cross_reference_pack)

    before_by_id = _findings_by_rule_id(baseline_findings)
    after_by_id = _findings_by_rule_id(projected_findings)

    findings_diff = []
    for rule_id, before in before_by_id.items():
        after = after_by_id.get(rule_id)
        if after is None:
            continue  # rule_pack changed shape mid-flight; nothing to diff
        if after.status != before.status:
            findings_diff.append({
                "rule_id": rule_id,
                "before_status": before.status,
                "after_status": after.status,
            })

    return {
        "before_score": risk_score(baseline_findings),
        "after_score": risk_score(projected_findings),
        "findings_diff": findings_diff,
    }
