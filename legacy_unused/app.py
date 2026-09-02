"""
HTTP API server for the compliance checker.

WHY THIS FILE EXISTS
--------------------
Before this, the repo had no runnable web server. `report_generator/router.py`
defined an APIRouter, but nothing ever created a FastAPI() app or included it,
so none of it was reachable. `main.py` and `pipeline.py` are CLI entry points.

This module is the missing HTTP layer. It does NOT reimplement any logic --
every endpoint delegates to the functions that already existed:

    converter.detection.resolve_vendor      -> vendor detection
    pipeline.process_config                 -> Block 2a + 2b analysis
    pipeline.apply_confirmation             -> human confirmation + memory
    compliance_engine.evaluator             -> rule evaluation
    report_generator.report_gen             -> PDF generation
    report_generator.router                 -> existing POST /api/reports/pdf

Run with:
    uvicorn app:app --reload --port 8000

Then open:
    http://127.0.0.1:8000/

NOTE ON STATE: scans are held in an in-memory dict. That is fine for a demo /
prototype, but it means scans are lost on restart and it will not work across
multiple worker processes. Swap SCANS for Redis or a table before deploying.
"""

from __future__ import annotations

import threading
import traceback
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from compliance_engine.evaluator import evaluate_report, load_rule_pack
from converter.detection import resolve_vendor
from pipeline import apply_confirmation, process_config
from report_generator.report_gen import generate_pdf_bytes, prepare_payload
from report_generator.router import router as reports_router

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(title="Network Config Compliance API", version="1.0.0")

# The frontend is served from this same origin by default, so CORS is not
# strictly needed -- but allow it so the HTML files also work if a teammate
# opens them from Live Server / a different port.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the router that already existed in the repo, unchanged.
# This keeps POST /api/reports/pdf exactly as report_generator/router.py defines it.
app.include_router(reports_router)


# --------------------------------------------------------------------------
# Scan store
# --------------------------------------------------------------------------

SCANS: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.Lock()

# The four steps the analyzing_configuration screen renders, in order.
STEPS = [
    "Parsing config",
    "Checking unknown lines",
    "Comparing against ruleset",
    "Generating report",
]

# The upload screen's <select> uses UI-friendly values ("cisco", "palo-alto").
# The backend's detector uses its own keys ("cisco_ios", "palo_alto"). Map here
# rather than editing the HTML.
VENDOR_ALIASES = {
    "auto": None,
    "": None,
    "cisco": "cisco_ios",
    "cisco_ios": "cisco_ios",
    "juniper": "juniper_junos",
    "juniper_junos": "juniper_junos",
    "palo-alto": "palo_alto",
    "palo_alto": "palo_alto",
    # No parser exists for Fortinet yet; passing it through lets the detector
    # flag the mismatch honestly instead of silently pretending we support it.
    "fortinet": "fortinet",
}

# Field types from shared/schema.py NormalizedConfig, used to coerce the
# string values that come back from the review screen's form controls.
FIELD_TYPES = {
    "ssh_enabled": "bool",
    "telnet_enabled": "bool",
    "session_timeout_seconds": "int",
    "logging_enabled": "bool",
    "password_encryption": "str",
    "banner_configured": "bool",
    "snmp_default_community": "list",
}


def _new_scan(filename: str, raw_text: str, declared_vendor: Optional[str]) -> str:
    scan_id = uuid.uuid4().hex[:12]
    with _LOCK:
        SCANS[scan_id] = {
            "id": scan_id,
            "filename": filename,
            "raw_text": raw_text,
            "declared_vendor": declared_vendor,
            "device": None,
            "config": {},
            "pending_confirmations": [],
            "evaluation": None,
            "state": "created",       # created|analyzing|needs_review|analyzed|evaluated|error
            "step_index": 0,
            "error": None,
        }
    return scan_id


def _get_scan(scan_id: str) -> Dict[str, Any]:
    scan = SCANS.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Unknown scan id '{scan_id}'")
    return scan


def _coerce_value(field: str, value: Any) -> Any:
    """Turn a form value into the type shared/schema.py expects for that field."""
    kind = FIELD_TYPES.get(field)
    if value is None or kind is None:
        return value
    if kind == "bool":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"true", "yes", "1", "on", "enabled"}
    if kind == "int":
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None
    if kind == "list":
        if isinstance(value, list):
            return value
        text = str(value).strip()
        return [part.strip() for part in text.split(",") if part.strip()] if text else []
    return str(value)


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------

class VendorOverride(BaseModel):
    vendor: Optional[str] = None


class ConfirmationItem(BaseModel):
    raw_line: str
    field: str
    value: Any = None


class ConfirmationBatch(BaseModel):
    confirmations: List[ConfirmationItem] = []
    confirmed_by: Optional[str] = None


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    rules, framework = load_rule_pack()
    return {"status": "ok", "framework": framework, "rule_count": len(rules)}


@app.get("/api/fields")
async def fields():
    """NormalizedConfig field names, so the review screen's dropdowns are
    populated from the real schema instead of hardcoded UI categories."""
    return {"fields": list(FIELD_TYPES.keys())}


@app.post("/api/scans")
async def create_scan(
    file: UploadFile = File(...),
    vendor: str = Form("auto"),
):
    """Screen 1 (upload_configuration). Stores the file and runs vendor
    detection only -- deliberately cheap and synchronous, so the upload screen
    can hand straight off to the vendor result screen."""
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raw_text = raw_bytes.decode("latin-1", errors="replace")

    declared = VENDOR_ALIASES.get((vendor or "auto").strip().lower(), None)
    scan_id = _new_scan(file.filename or "config.txt", raw_text, declared)

    detection = resolve_vendor(raw_text, declared)
    scan = _get_scan(scan_id)
    scan["device"] = {
        "vendor": detection["vendor"],
        "confidence": detection["confidence"],
        "needs_confirmation": detection["needs_confirmation"],
        "reason": detection["reason"],
        "hostname": _guess_hostname(raw_text),
    }
    scan["detection"] = detection

    return {
        "scan_id": scan_id,
        "filename": scan["filename"],
        "declared_vendor": declared,
        "device": scan["device"],
        "needs_confirmation": detection["needs_confirmation"],
        "line_count": len(raw_text.splitlines()),
    }


def _guess_hostname(raw_text: str) -> Optional[str]:
    """Best-effort hostname pull so the report screen has something real to
    show. Purely cosmetic -- never feeds into rule evaluation."""
    import re
    for pattern in (
        r"^hostname\s+(\S+)",
        r"^set system host-name\s+(\S+)",
        r"^set deviceconfig system hostname\s+(\S+)",
    ):
        match = re.search(pattern, raw_text, re.MULTILINE)
        if match:
            return match.group(1)
    return None


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = _get_scan(scan_id)
    return {
        "scan_id": scan["id"],
        "filename": scan["filename"],
        "state": scan["state"],
        "device": scan["device"],
        "declared_vendor": scan["declared_vendor"],
        "config": scan["config"],
        "pending_count": len(scan["pending_confirmations"]),
        "error": scan["error"],
    }


@app.get("/api/scans/{scan_id}/vendor")
async def get_vendor(scan_id: str):
    """Screen 2 (vendor_detection_result)."""
    scan = _get_scan(scan_id)
    detection = scan.get("detection") or {}
    return {
        "scan_id": scan["id"],
        "filename": scan["filename"],
        "vendor": scan["device"]["vendor"] if scan["device"] else None,
        "confidence": scan["device"]["confidence"] if scan["device"] else None,
        "reason": scan["device"]["reason"] if scan["device"] else None,
        "needs_confirmation": bool(detection.get("needs_confirmation")),
        "declared_vendor": scan["declared_vendor"],
        "hostname": (scan["device"] or {}).get("hostname"),
    }


@app.post("/api/scans/{scan_id}/vendor")
async def set_vendor(scan_id: str, payload: VendorOverride):
    """Screen 2 actions: 'Proceed with X anyway' / 'Switch to Y'."""
    scan = _get_scan(scan_id)
    chosen = VENDOR_ALIASES.get((payload.vendor or "").strip().lower(), payload.vendor)
    if chosen:
        scan["device"] = dict(scan["device"] or {})
        scan["device"]["vendor"] = chosen
        scan["device"]["confidence"] = "user_confirmed"
        scan["device"]["needs_confirmation"] = False
        scan["device"]["reason"] = "Confirmed by user on the vendor detection screen."
        scan["declared_vendor"] = chosen
    return {"scan_id": scan_id, "device": scan["device"]}


def _run_analysis(scan_id: str) -> None:
    """Background worker for the analyzing screen. Runs the existing
    pipeline.process_config and records step progress as it goes."""
    scan = SCANS.get(scan_id)
    if scan is None:
        return
    try:
        scan["state"] = "analyzing"
        scan["step_index"] = 0

        result = process_config(scan["raw_text"], scan.get("declared_vendor"))
        scan["step_index"] = 1

        device = dict(result.get("device") or {})
        # Keep a user-confirmed vendor -- process_config re-detects from
        # scratch and would otherwise overwrite the human's choice.
        existing = scan.get("device") or {}
        if existing.get("confidence") == "user_confirmed":
            device["vendor"] = existing["vendor"]
            device["confidence"] = "user_confirmed"
            device["needs_confirmation"] = False
        device["hostname"] = existing.get("hostname") or _guess_hostname(scan["raw_text"])

        scan["device"] = device
        scan["config"] = result.get("config") or {}
        scan["pending_confirmations"] = result.get("pending_confirmations") or []
        scan["step_index"] = 2

        if scan["pending_confirmations"]:
            scan["state"] = "needs_review"
        else:
            scan["state"] = "analyzed"
    except Exception as exc:  # noqa: BLE001 - surface any pipeline failure to the UI
        scan["state"] = "error"
        scan["error"] = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()


@app.post("/api/scans/{scan_id}/analyze")
async def start_analysis(scan_id: str):
    """Screen 3 (analyzing_configuration) kicks this off, then polls /status."""
    scan = _get_scan(scan_id)
    if scan["state"] == "analyzing":
        return {"scan_id": scan_id, "state": "analyzing"}
    scan["error"] = None
    thread = threading.Thread(target=_run_analysis, args=(scan_id,), daemon=True)
    thread.start()
    return {"scan_id": scan_id, "state": "analyzing"}


@app.get("/api/scans/{scan_id}/status")
async def analysis_status(scan_id: str):
    scan = _get_scan(scan_id)
    return {
        "scan_id": scan_id,
        "state": scan["state"],
        "step_index": scan["step_index"],
        "steps": STEPS,
        "current_step": STEPS[min(scan["step_index"], len(STEPS) - 1)],
        "pending_count": len(scan["pending_confirmations"]),
        "error": scan["error"],
    }


@app.get("/api/scans/{scan_id}/pending")
async def get_pending(scan_id: str):
    """Screen 4 (review_unknown_lines)."""
    scan = _get_scan(scan_id)
    return {
        "scan_id": scan_id,
        "fields": list(FIELD_TYPES.keys()),
        "pending_confirmations": scan["pending_confirmations"],
        "config": scan["config"],
    }


@app.post("/api/scans/{scan_id}/confirmations")
async def post_confirmations(scan_id: str, batch: ConfirmationBatch):
    """Screen 4 'Confirm All & Continue'. Delegates to pipeline.apply_confirmation
    so each answer is written to the memory layer (block2b/memory.py) and merged
    into the config."""
    scan = _get_scan(scan_id)
    config = dict(scan["config"])
    vendor = (scan["device"] or {}).get("vendor")

    applied = 0
    for item in batch.confirmations:
        value = _coerce_value(item.field, item.value)
        config = apply_confirmation(
            config,
            raw_line=item.raw_line,
            field=item.field,
            value=value,
            vendor_hint=vendor,
            confirmed_by=batch.confirmed_by,
        )
        applied += 1

    confirmed_lines = {item.raw_line for item in batch.confirmations}
    scan["config"] = config
    scan["pending_confirmations"] = [
        pending for pending in scan["pending_confirmations"]
        if pending.get("raw_line") not in confirmed_lines
    ]
    if not scan["pending_confirmations"]:
        scan["state"] = "analyzed"

    return {
        "scan_id": scan_id,
        "applied": applied,
        "config": scan["config"],
        "remaining": len(scan["pending_confirmations"]),
    }


def _build_evaluation(scan: Dict[str, Any]) -> Dict[str, Any]:
    rules, framework = load_rule_pack()
    evaluation = evaluate_report(
        {"device": scan["device"] or {}, "config": scan["config"]},
        rules,
    )
    evaluation["framework"] = framework
    scan["evaluation"] = evaluation
    scan["state"] = "evaluated"
    return evaluation


@app.post("/api/scans/{scan_id}/evaluate")
async def evaluate(scan_id: str):
    scan = _get_scan(scan_id)
    return _build_evaluation(scan)


@app.get("/api/scans/{scan_id}/report")
async def get_report(scan_id: str):
    """Screen 5 (compliance_report_dashboard). Returns the evaluation plus the
    summary numbers report_generator already knows how to compute, so the
    dashboard and the PDF can never disagree."""
    scan = _get_scan(scan_id)
    evaluation = scan.get("evaluation") or _build_evaluation(scan)
    framework = evaluation.get("framework", "CIS")
    payload = prepare_payload(evaluation, framework=framework)
    return {
        "scan_id": scan_id,
        "filename": scan["filename"],
        "device": payload["device"],
        "framework": payload["framework"],
        "warning": payload["warning"],
        "meta": payload["meta"],
        "summary": payload["summary"],
        "findings": payload["findings"],
    }


@app.get("/api/scans/{scan_id}/report.pdf")
async def get_report_pdf(scan_id: str):
    """Convenience wrapper around the same generator POST /api/reports/pdf uses,
    so the dashboard's download button only needs a scan id."""
    scan = _get_scan(scan_id)
    evaluation = scan.get("evaluation") or _build_evaluation(scan)
    framework = evaluation.get("framework", "CIS")
    try:
        pdf_bytes = generate_pdf_bytes(evaluation, framework=framework)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

    hostname = (scan["device"] or {}).get("hostname") or "network_device"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="Compliance_Report_{hostname}.pdf"'},
    )


# --------------------------------------------------------------------------
# Static frontend
# --------------------------------------------------------------------------

# The HTML filenames contain spaces, so they are URL-encoded here once and
# referenced by these constants everywhere else.
SCREEN_FILES = {
    "upload": "upload_configuration/code 4 uc.html",
    "vendor": "vendor_detection_result/code 5 vdr.html",
    "analyzing": "analyzing_configuration/code1 ac.html",
    "review": "review_unknown_lines/code 3 rul.html",
    "report": "compliance_report_dashboard/code 2 cr.html",
}


@app.get("/")
async def index():
    return RedirectResponse(url="/ui/" + urllib.parse.quote(SCREEN_FILES["upload"]))


if FRONTEND_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="ui")
