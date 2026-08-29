"""
report_generator.generator
----------------------------
Phase 5.5 -- turns a ``shared.schema.ComplianceReport`` into a PDF with:

  1. Device Identification (vendor, hostname, serial, OS version)
  2. Compliance Findings table -- rule_id / status / severity / field,
     with PASS / FAIL / UNKNOWN as three visually distinct states
     (UNKNOWN reads as "could not determine", never as a failure)
  3. Remediation Paths -- ``Finding.remediation_cli`` reproduced
     VERBATIM for every FAIL finding, never touched by an LLM
  4. A short LLM-generated plain-English risk explanation per FAIL
     finding (via ``report_generator.explain``), kept in its own
     clearly-labelled block, never merged into the remediation text

Uses ReportLab (pure Python, no system-library dependency), per the
handoff doc's "WeasyPrint, or ReportLab if that's easier".

Two-layer design so the logic is testable without touching PDF bytes:
  - ``build_findings_rows()`` does all the data assembly + decides
    which findings get an LLM explanation (FAIL only). Pure data in,
    pure data out -- this is what tests exercise directly.
  - ``generate_pdf()`` takes those rows and lays out the actual PDF.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether,
)

from report_generator.explain import explain_finding, ExplanationError

# Status -> (display label, row background, text color)
_STATUS_STYLE = {
    "PASS": ("PASS", colors.HexColor("#e6f4ea"), colors.HexColor("#1e7e34")),
    "FAIL": ("FAIL", colors.HexColor("#fdecea"), colors.HexColor("#c62828")),
    "UNKNOWN": ("COULD NOT DETERMINE", colors.HexColor("#fff8e1"), colors.HexColor("#8a6d00")),
}

ExplainFn = Callable[..., str]


@dataclass
class FindingRow:
    rule_id: str
    status: str          # "PASS" | "FAIL" | "UNKNOWN"
    severity: str
    field: str
    remediation_cli: Optional[str]     # verbatim, only set for FAIL
    llm_explanation: Optional[str]     # only set for FAIL, None if generation failed
    explanation_error: Optional[str]   # set if the LLM call failed, for graceful fallback


def build_findings_rows(
    report,
    explain_fn: Optional[ExplainFn] = None,
) -> list[FindingRow]:
    """Pure data-assembly step. Calls ``explain_fn`` ONLY for FAIL
    findings -- PASS and UNKNOWN never get an LLM call. If
    ``explain_fn`` raises, the row still gets built (with
    ``llm_explanation=None`` and the error recorded) so one bad AI call
    can't take down the whole report.
    """
    explain = explain_fn or explain_finding
    rows: list[FindingRow] = []
    for finding in report.findings:
        llm_explanation = None
        explanation_error = None
        remediation_cli = None
        if finding.status == "FAIL":
            remediation_cli = finding.remediation_cli  # verbatim, untouched
            try:
                llm_explanation = explain(finding)
            except ExplanationError as e:
                explanation_error = str(e)
        rows.append(FindingRow(
            rule_id=finding.rule_id,
            status=finding.status,
            severity=finding.severity,
            field=finding.field_checked,
            remediation_cli=remediation_cli,
            llm_explanation=llm_explanation,
            explanation_error=explanation_error,
        ))
    return rows


def _device_table(device) -> Table:
    rows = [
        ["Vendor", getattr(device, "vendor", None) or "—"],
        ["Hostname", getattr(device, "hostname", None) or "—"],
        ["Serial", getattr(device, "serial_number", None) or "—"],
        ["OS Version", getattr(device, "os_version", None) or "—"],
    ]
    t = Table(rows, colWidths=[4 * cm, 10 * cm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#dddddd")),
    ]))
    return t


def _findings_table(rows: list[FindingRow], styles) -> Table:
    header = ["Rule ID", "Status", "Severity", "Field Checked"]
    data = [header]
    row_colors = [None]  # header has its own style
    for r in rows:
        label, bg, fg = _STATUS_STYLE[r.status]
        status_para = Paragraph(
            f'<font color="#{fg.hexval()[2:]}"><b>{label}</b></font>', styles["Normal"]
        )
        data.append([r.rule_id, status_para, r.severity, r.field])
        row_colors.append(bg)

    t = Table(data, colWidths=[3.5 * cm, 4.5 * cm, 2.5 * cm, 5 * cm], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, bg in enumerate(row_colors):
        if bg is not None:
            style.append(("BACKGROUND", (0, i), (-1, i), bg))
    t.setStyle(TableStyle(style))
    return t


def _remediation_block(row: FindingRow, styles) -> KeepTogether:
    cli_style = ParagraphStyle(
        "cli", parent=styles["Code"], fontSize=9, leading=12, leftIndent=0,
    )
    explain_style = ParagraphStyle(
        "explain_block", parent=styles["Normal"], leftIndent=6,
        borderColor=colors.HexColor("#c62828"), borderWidth=0, textColor=colors.HexColor("#333333"),
        spaceBefore=4,
    )
    # A single-cell Table (rather than Paragraph backColor/borderPadding,
    # which reportlab can mis-measure and overlap with the flowable above
    # it) gives a reliable grey "code block" background.
    cli_text = (row.remediation_cli or "No remediation available for this vendor.").replace("\n", "<br/>")
    cli_table = Table([[Paragraph(cli_text, cli_style)]], colWidths=[16 * cm])
    cli_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f5f5f5")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    flow = [
        Paragraph(f"<b>{row.rule_id}</b> &mdash; {row.field} (severity: {row.severity})",
                   styles["Heading4"]),
        Spacer(1, 6),
        Paragraph("Remediation (verbatim, deterministic):", styles["Normal"]),
        Spacer(1, 3),
        cli_table,
        Spacer(1, 4),
    ]
    if row.llm_explanation:
        flow.append(Paragraph("<i>Why this matters:</i>", styles["Normal"]))
        flow.append(Paragraph(row.llm_explanation, explain_style))
    elif row.explanation_error:
        # Graceful fallback: never fabricate a narrative, just say so.
        flow.append(Paragraph(
            "<i>Why this matters:</i> (explanation unavailable — showing rule note instead)",
            styles["Normal"],
        ))
    flow.append(Spacer(1, 10))
    return KeepTogether(flow)


def generate_pdf(
    report,
    output_path: str | Path,
    explain_fn: Optional[ExplainFn] = None,
) -> str:
    """Renders ``report`` (a ``shared.schema.ComplianceReport``) to a
    PDF at ``output_path``. Returns the path as a string.
    """
    rows = build_findings_rows(report, explain_fn=explain_fn)
    styles = getSampleStyleSheet()

    output_path = Path(output_path)
    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
    )

    story = []
    story.append(Paragraph("Network Compliance Report", styles["Title"]))
    story.append(Paragraph(
        f"Framework: {report.framework} &nbsp;|&nbsp; "
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Device Identification", styles["Heading2"]))
    story.append(_device_table(report.device))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Compliance Findings", styles["Heading2"]))
    story.append(_findings_table(rows, styles))
    story.append(Spacer(1, 14))

    fail_rows = [r for r in rows if r.status == "FAIL"]
    if fail_rows:
        story.append(Paragraph("Remediation Paths", styles["Heading2"]))
        for row in fail_rows:
            story.append(_remediation_block(row, styles))
    else:
        story.append(Paragraph("No FAIL findings — no remediation required.", styles["Normal"]))

    doc.build(story)
    return str(output_path)
