"""
report_generator.explain
-------------------------
Phase 5.5 -- generates a short plain-English risk explanation for a
single FAIL ``Finding``, via the Claude API, expanding on the
deterministic ``Finding.explanation`` seed text that already comes out
of ``compliance_engine.evaluate``.

This module NEVER touches ``Finding.remediation_cli``. That text is
rule-pack data (deterministic, vendor-verified CLI) and must reach the
PDF byte-for-byte. The LLM only ever produces the *separate* narrative
paragraph that sits next to it in the report -- see
``report_generator.generator`` for how the two are kept apart.

Mirrors the injectable-API-call pattern used in
``ai_fallback.classify`` so this module is fully testable without
network access or an API key unless the real path actually runs.
"""

from __future__ import annotations

from typing import Callable, Optional

DEFAULT_MODEL = "claude-sonnet-4-6"

# (finding, model) -> raw text of the model's reply.
# Tests inject a fake implementation here.
ApiCallFn = Callable[[object, str], str]


class ExplanationError(RuntimeError):
    """Raised when the AI call itself fails; callers should fall back
    to the deterministic ``Finding.explanation`` seed text rather than
    let a whole report fail to generate over one narrative paragraph."""


def _default_api_call(finding, model: str) -> str:
    """Real Claude API call. `anthropic` is imported lazily so importing
    this module never requires the package or a configured API key
    unless this code path actually runs."""
    import anthropic  # optional dependency, only needed for real calls

    client = anthropic.Anthropic()
    prompt = _build_explanation_prompt(finding)
    response = client.messages.create(
        model=model,
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(
        block.text for block in response.content
        if getattr(block, "type", None) == "text"
    ).strip()


def _build_explanation_prompt(finding) -> str:
    seed = finding.explanation or f"The {finding.field_checked} check failed rule {finding.rule_id}."
    return (
        "You are writing a short, plain-English risk explanation for a "
        "network compliance report, for a non-technical reader (e.g. an "
        "auditor or manager), NOT the CLI remediation itself.\n\n"
        f"Rule ID: {finding.rule_id}\n"
        f"Field checked: {finding.field_checked}\n"
        f"Severity: {finding.severity}\n"
        f"Deterministic finding note: {seed}\n\n"
        "Write 2-4 sentences explaining, in plain language, what this "
        "failure means and why it matters from a security/compliance "
        "standpoint. Do NOT include any CLI commands, configuration "
        "syntax, or step-by-step remediation instructions -- that is "
        "shown separately. Respond with ONLY the explanation text, no "
        "preamble, no headers."
    )


def explain_finding(
    finding,
    *,
    model: str = DEFAULT_MODEL,
    api_call_fn: Optional[ApiCallFn] = None,
) -> str:
    """Returns a plain-English explanation for one FAIL finding.

    Callers (see ``report_generator.generator.build_findings_rows``)
    are expected to only call this for ``status == "FAIL"`` findings --
    this function does not enforce that itself so it stays a simple,
    directly-testable unit.

    On any AI failure, raises ``ExplanationError`` rather than
    returning something invented; the caller decides whether to fall
    back to ``finding.explanation`` or surface the error.
    """
    call = api_call_fn or _default_api_call
    try:
        text = call(finding, model)
    except Exception as e:  # noqa: BLE001 - deliberately broad, see docstring
        raise ExplanationError(
            f"Explanation generation failed for {finding.rule_id}: {e}"
        ) from e
    if not text:
        raise ExplanationError(f"Empty explanation returned for {finding.rule_id}")
    return text
