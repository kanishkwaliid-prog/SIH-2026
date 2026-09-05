import os
import sys
import platform
from datetime import datetime, timezone
from jinja2 import Template

# macOS Homebrew Library Path Fix for WeasyPrint
if platform.system() == "Darwin":
    homebrew_lib = "/opt/homebrew/lib" if os.path.exists("/opt/homebrew/lib") else "/usr/local/lib"
    os.environ["DYLD_LIBRARY_PATH"] = f"{homebrew_lib}:{os.environ.get('DYLD_LIBRARY_PATH', '')}"

from weasyprint import HTML

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
    @page {
        size: A4;
        margin: 16mm 14mm 18mm 14mm;
        background-color: #f8fafc;
        @bottom-right {
            content: "Page " counter(page) " of " counter(pages);
            font-family: -apple-system, sans-serif;
            font-size: 8pt;
            color: #64748b;
        }
    }
    *, *::before, *::after { box-sizing: border-box; }
    body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1e293b; background-color: #f8fafc; font-size: 9.5pt; line-height: 1.45; }
    .header-banner { background-color: #0f172a; color: #ffffff; padding: 18px 20px; border-radius: 6px; margin-bottom: 16px; }
    .header-table { width: 100%; border-collapse: collapse; }
    .header-title { font-size: 16pt; font-weight: 700; color: #ffffff; margin: 0; }
    .header-subtitle { font-size: 9pt; color: #94a3b8; margin-top: 3px; }
    .score-box { display: inline-block; background-color: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 8px 14px; text-align: center; }
    .score-value { font-size: 18pt; font-weight: 800; color: {% if summary.score >= 80 %}#4ade80{% elif summary.score >= 60 %}#fbbf24{% else %}#f87171{% endif %}; line-height: 1; }
    .score-label { font-size: 7pt; text-transform: uppercase; color: #94a3b8; margin-top: 4px; }
    h2 { font-size: 12pt; font-weight: 700; color: #0f172a; border-left: 4px solid #2563eb; padding-left: 8px; margin-top: 18px; margin-bottom: 10px; page-break-after: avoid; }
    h3 { font-size: 10.5pt; font-weight: 600; color: #1e293b; margin-top: 12px; margin-bottom: 6px; page-break-after: avoid; }
    .exec-summary { background-color: #ffffff; border: 1px solid #e2e8f0; border-left: 4px solid #0284c7; border-radius: 4px; padding: 12px 14px; margin-bottom: 16px; }
    .exec-summary-title { font-size: 8.5pt; font-weight: 700; text-transform: uppercase; color: #0369a1; margin-bottom: 4px; }
    .exec-summary-p { margin: 0; font-size: 9pt; color: #334155; }
    .warning-box { background-color: #fffbebf5; border: 1px solid #fef3c7; border-left: 4px solid #d97706; padding: 10px; border-radius: 4px; font-size: 8.5pt; color: #92400e; margin-bottom: 14px; }
    .grid-2col { width: 100%; border-collapse: separate; border-spacing: 12px 0; margin-left: -12px; margin-right: -12px; margin-bottom: 16px; }
    .grid-cell { vertical-align: top; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; }
    .info-table { width: 100%; border-collapse: collapse; }
    .info-table td { padding: 4px 0; font-size: 8.5pt; }
    .info-label { color: #64748b; font-weight: 500; width: 42%; }
    .info-value { color: #0f172a; font-weight: 600; font-family: monospace; font-size: 8.5pt; }
    .metrics-table { width: 100%; border-collapse: separate; border-spacing: 8px 0; margin-bottom: 16px; }
    .metric-card { background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 10px; text-align: center; }
    .metric-card.critical { border-top: 3px solid #dc2626; }
    .metric-card.high { border-top: 3px solid #ea580c; }
    .metric-card.medium { border-top: 3px solid #d97706; }
    .metric-card.passed { border-top: 3px solid #16a34a; }
    .metric-num { font-size: 14pt; font-weight: 800; line-height: 1.1; }
    .metric-num.critical { color: #dc2626; }
    .metric-num.high { color: #ea580c; }
    .metric-num.medium { color: #d97706; }
    .metric-num.passed { color: #16a34a; }
    .metric-lbl { font-size: 7.5pt; color: #64748b; text-transform: uppercase; font-weight: 600; margin-top: 2px; }
    .findings-table { width: 100%; border-collapse: collapse; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 20px; }
    .findings-table th { background-color: #f1f5f9; color: #475569; font-size: 8pt; text-transform: uppercase; padding: 8px 10px; text-align: left; border-bottom: 1px solid #cbd5e1; }
    .findings-table td { padding: 8px 10px; font-size: 8.5pt; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
    .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 7.5pt; font-weight: 700; text-transform: uppercase; }
    .badge-pass { background-color: #dcfce7; color: #15803d; }
    .badge-fail { background-color: #fee2e2; color: #b91c1c; }
    .badge-not_evaluated { background-color: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }
    .badge-critical { background-color: #fef2f2; color: #991b1b; border: 1px solid #fca5a5; }
    .badge-high { background-color: #fff7ed; color: #c2410c; border: 1px solid #fdba74; }
    .badge-medium { background-color: #fefce8; color: #a16207; border: 1px solid #fde047; }
    .badge-low { background-color: #eff6ff; color: #1d4ed8; border: 1px solid #93c5fd; }
    .field-tag { font-family: monospace; background-color: #f1f5f9; color: #0f172a; padding: 1px 4px; border-radius: 3px; font-size: 8pt; }
    .remediation-card { background-color: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px 14px; margin-bottom: 14px; page-break-inside: avoid; }
    .remediation-header { width: 100%; border-collapse: collapse; margin-bottom: 8px; }
    .remediation-title { font-size: 9.5pt; font-weight: 700; color: #0f172a; }
    .risk-box { background-color: #fef2f2; border-left: 3px solid #ef4444; padding: 6px 10px; border-radius: 0 4px 4px 0; margin-bottom: 8px; font-size: 8.5pt; color: #7f1d1d; }
    .tech-details-box { background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; padding: 6px 10px; margin-bottom: 8px; font-size: 8pt; color: #475569; }
    .cli-box { background-color: #0f172a; color: #38bdf8; font-family: monospace; font-size: 8.5pt; padding: 10px 12px; border-radius: 4px; white-space: pre-wrap; word-break: break-all; margin: 0; }
    .cli-label { font-size: 7.5pt; font-weight: 700; text-transform: uppercase; color: #94a3b8; margin-bottom: 4px; }
</style>
</head>
<body>
    <div class="header-banner">
        <table class="header-table">
            <tr>
                <td>
                    <div class="header-title">Network Compliance Audit & Remediation</div>
                    <div class="header-subtitle">Target Standard: {{ framework|default('CIS Benchmarks') }} • NetShield AI Engine</div>
                </td>
                <td style="text-align: right;">
                    <div class="score-box">
                        <div class="score-value">{{ summary.score }}%</div>
                        <div class="score-label">Compliance Score</div>
                    </div>
                </td>
            </tr>
        </table>
    </div>

    {% if warning %}
    <div class="warning-box">
        <strong>Engine Warning:</strong> {{ warning }}
    </div>
    {% endif %}

    <div class="exec-summary">
        <div class="exec-summary-title">Executive Summary</div>
        <div class="exec-summary-p">
            Automated analysis evaluated device <strong>{{ device.hostname|default(device.vendor|default('Network Device')) }}</strong>. 
            The system processed {{ summary.total_checks }} rules and identified <strong>{{ summary.failed_count }} non-compliant finding(s)</strong>.
            Review the remediation steps in Section 3 to mitigate active risks.
        </div>
    </div>

    <h2>1. Device Identification</h2>
    <table class="grid-2col">
        <tr>
            <td class="grid-cell" style="width: 50%;">
                <h3 style="margin-top:0;">Hardware & OS Details</h3>
                <table class="info-table">
                    <tr><td class="info-label">Hostname:</td><td class="info-value">{{ device.hostname|default('N/A') }}</td></tr>
                    <tr><td class="info-label">Vendor:</td><td class="info-value">{{ device.vendor|default('Unknown') }}</td></tr>
                    <tr><td class="info-label">Hardware Model:</td><td class="info-value">{{ device.hardware_model|default('N/A') }}</td></tr>
                    <tr><td class="info-label">Serial Number:</td><td class="info-value">{{ device.serial_number|default('N/A') }}</td></tr>
                    <tr><td class="info-label">OS Version:</td><td class="info-value">{{ device.os_version|default('N/A') }}</td></tr>
                </table>
            </td>
            <td class="grid-cell" style="width: 50%;">
                <h3 style="margin-top:0;">Audit Metadata</h3>
                <table class="info-table">
                    <tr><td class="info-label">IP Address:</td><td class="info-value">{{ device.ip_address|default('N/A') }}</td></tr>
                    <tr><td class="info-label">Device Type:</td><td class="info-value">{{ device.device_type|default('Network Device') }}</td></tr>
                    <tr><td class="info-label">Scan Date:</td><td class="info-value">{{ meta.scan_date }}</td></tr>
                    <tr><td class="info-label">Framework:</td><td class="info-value">{{ framework|default('CIS Baseline') }}</td></tr>
                    <tr><td class="info-label">Audit ID:</td><td class="info-value">{{ meta.job_id }}</td></tr>
                </table>
            </td>
        </tr>
    </table>

    <table class="metrics-table">
        <tr>
            <td style="width: 25%;">
                <div class="metric-card critical">
                    <div class="metric-num critical">{{ summary.critical_count }}</div>
                    <div class="metric-lbl">Critical Risk</div>
                </div>
            </td>
            <td style="width: 25%;">
                <div class="metric-card high">
                    <div class="metric-num high">{{ summary.high_count }}</div>
                    <div class="metric-lbl">High Risk</div>
                </div>
            </td>
            <td style="width: 25%;">
                <div class="metric-card medium">
                    <div class="metric-num medium">{{ summary.medium_count }}</div>
                    <div class="metric-lbl">Medium / Low</div>
                </div>
            </td>
            <td style="width: 25%;">
                <div class="metric-card passed">
                    <div class="metric-num passed">{{ summary.passed_count }}</div>
                    <div class="metric-lbl">Passed Checks</div>
                </div>
            </td>
        </tr>
    </table>

    <h2>2. Compliance Findings Summary</h2>
    <table class="findings-table">
        <thead>
            <tr>
                <th style="width: 14%;">Rule ID</th>
                <th style="width: 12%;">Status</th>
                <th style="width: 12%;">Severity</th>
                <th style="width: 25%;">Field Checked</th>
                <th>Rule Explanation</th>
            </tr>
        </thead>
        <tbody>
            {% for item in findings %}
            <tr>
                <td><strong>{{ item.rule_id }}</strong></td>
                <td><span class="badge badge-{{ item.status|lower }}">{{ item.status }}</span></td>
                <td><span class="badge badge-{{ item.severity|lower|default('low') }}">{{ item.severity|default('INFO')|upper }}</span></td>
                <td><span class="field-tag">{{ item.field_checked }}</span></td>
                <td>{{ item.explanation|default('No description provided.') }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <h2>3. Remediation Paths (Vendor CLI Fixes)</h2>
    {% for item in findings %}
        {% if item.status == 'FAIL' %}
        <div class="remediation-card">
            <table class="remediation-header">
                <tr>
                    <td class="remediation-title">Rule {{ item.rule_id }}: {{ item.explanation|default(item.rule_id) }}</td>
                    <td style="text-align: right;">
                        <span class="badge badge-{{ item.severity|lower|default('low') }}">{{ item.severity|default('INFO')|upper }}</span>
                        <span class="badge badge-fail" style="margin-left: 4px;">FAIL</span>
                    </td>
                </tr>
            </table>

            <div class="risk-box">
                {{ item.risk_explanation }}
            </div>

            <div class="tech-details-box">
                <strong>Rule ID:</strong> {{ item.rule_id }} &bull; 
                <strong>Field Checked:</strong> <span class="field-tag">{{ item.field_checked }}</span> &bull; 
                <strong>Observed Value:</strong> <code>{{ item.observed_value }}</code>
            </div>

            <div class="cli-label">How to fix? ({{ device.vendor|default('Generic') }}):</div>
            <pre class="cli-box">{{ item.remediation_cli|default('# No automatic remediation script provided for this rule.') }}</pre>
        </div>
        {% endif %}
    {% endfor %}
</body>
</html>
"""

def prepare_payload(raw_eval_result: dict, framework: str = "CIS Baseline") -> dict:
    device = raw_eval_result.get("device") or {}
    findings_raw = raw_eval_result.get("findings") or []
    
    passed_count = sum(1 for f in findings_raw if f.get("status") == "PASS")
    failed_count = sum(1 for f in findings_raw if f.get("status") == "FAIL")
    not_eval_count = sum(1 for f in findings_raw if f.get("status") == "NOT_EVALUATED")
    total_checks = len(findings_raw)
    
    evaluated_total = passed_count + failed_count
    score = round((passed_count / evaluated_total) * 100, 1) if evaluated_total > 0 else 100.0
    
    critical_count = sum(1 for f in findings_raw if f.get("status") == "FAIL" and str(f.get("severity")).upper() == "CRITICAL")
    high_count = sum(1 for f in findings_raw if f.get("status") == "FAIL" and str(f.get("severity")).upper() == "HIGH")
    medium_count = sum(1 for f in findings_raw if f.get("status") == "FAIL" and str(f.get("severity")).upper() in ["MEDIUM", "LOW"])
    
    processed_findings = []
    for f in findings_raw:
        item = dict(f)
        item["observed_value"] = item.get("actual") if item.get("actual") is not None else "null"
        item["risk_explanation"] = item.get("explanation") or f"Field '{item.get('field_checked')}' violated standard baseline rules."
        processed_findings.append(item)
        
    return {
        "device": device,
        "framework": framework,
        "warning": raw_eval_result.get("warning"),
        "meta": {
            "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "job_id": f"SIH2026-JOB-{os.urandom(2).hex().upper()}"
        },
        "summary": {
            "score": score,
            "total_checks": total_checks,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "not_evaluated_count": not_eval_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count
        },
        "findings": processed_findings
    }

def generate_pdf_bytes(raw_eval_result: dict, framework: str = "CIS Baseline") -> bytes:
    payload = prepare_payload(raw_eval_result, framework)
    template = Template(REPORT_TEMPLATE)
    rendered_html = template.render(**payload)
    return HTML(string=rendered_html).write_pdf()

def generate_pdf_file(raw_eval_result: dict, output_filename: str = "compliance_report.pdf", framework: str = "CIS Baseline"):
    pdf_bytes = generate_pdf_bytes(raw_eval_result, framework)
    with open(output_filename, "wb") as f:
        f.write(pdf_bytes)
    print(f"✅ PDF successfully generated: {output_filename}")