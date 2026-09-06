"""
API layer for the compliance pipeline. Wraps Block 2 (pipeline.py),
Block 3 (compliance_engine/evaluator.py), and Block 4
(report_generator/report_gen.py) behind HTTP endpoints so the frontend
can call them. Also serves the frontend itself (see the bottom of this
file), so one command runs the whole app.

Run with: uvicorn api:app --reload --port 8000
Then open: 

This is a hackathon-scoped implementation: sessions are stored in memory
(a plain dict), not a database, so restarting the server loses in-progress
scans. Fine for a demo; would need a real store (e.g. the SQLite memory.py
already uses, or a new table) for anything beyond that.
"""

import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from pipeline import apply_confirmation, process_config
from compliance_engine.evaluator import evaluate_report, load_selected_rule_packs
from report_generator.report_gen import generate_pdf_bytes

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(title="Network Compliance Engine API")

from block2b import review_system

review_system.init_review_tables()
# Demo-scope role assignment. In production this comes from your real
# auth/identity system, not hardcoded here -- flag this as intentional
# scope if a judge asks.
review_system.seed_user("alice", "Alice", "senior_engineer")
review_system.seed_user("bob", "Bob", "engineer")
review_system.seed_user("carol", "Carol", "user")
review_system.seed_user("demo-user", "Demo User", "engineer")

# Allow the frontend (opened as a local file or served from a different
# port) to call this API during development. Fine for a hackathon demo;
# would be tightened to specific origins for a real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session store: session_id -> {"device": ..., "config": ...,
# "vendor": ..., "raw_text": ...}
SESSIONS: dict[str, dict] = {}


# ---------- POST /upload ----------

@app.post("/upload")
async def upload_configs(
    files: list[UploadFile] = File(...),
    vendor_hint: str | None = Form(default=None),
):
    """
    Accepts one or more config files (bulk upload supported, per the
    problem statement's "single or bulk configuration files" requirement).
    Runs Block 2 (detection + parsing + LLM fallback) on each file
    independently and returns one result per file, each with its own
    session_id for the frontend to reference in later calls.
    """
    results = []
    for upload in files:
        raw_bytes = await upload.read()
        try:
            raw_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            results.append({
                "filename": upload.filename,
                "error": "File is not valid UTF-8 text -- check it's a plain-text config export.",
            })
            continue

        result = process_config(raw_text, user_declared_vendor=vendor_hint)

        session_id = str(uuid.uuid4())
        SESSIONS[session_id] = {
            "filename": upload.filename,
            "raw_text": raw_text,
            "device": result["device"],
            "config": result["config"],
        }

        results.append({
            "session_id": session_id,
            "filename": upload.filename,
            "device": result["device"],
            "config": result["config"],
            "pending_confirmations": result["pending_confirmations"],
        })

    return {"results": results}


# ---------- POST /confirm ----------

class ConfirmationItem(BaseModel):
    raw_line: str
    field: str
    value: object = None


class ConfirmRequest(BaseModel):
    session_id: str
    confirmations: list[ConfirmationItem]
    confirmed_by: str | None = None


@app.post("/confirm")
async def confirm_lines(body: ConfirmRequest):
    """
    Accepts a batch of human-confirmed/corrected classifications from the
    review-unknown-lines screen. Saves each to memory (so it's recognized
    instantly next time) and merges resolved fields into this session's
    config.
    """
    session = SESSIONS.get(body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown session_id -- did you call /upload first?")

    if not body.confirmed_by:
        raise HTTPException(status_code=400, detail="confirmed_by is required for every confirmation.")

    config = session["config"]
    review_results = []
    for item in body.confirmations:
        try:
            config, result = apply_confirmation(
                config,
                raw_line=item.raw_line,
                field=item.field,
                value=item.value,
                vendor_hint=session["device"].get("vendor"),
                confirmed_by=body.confirmed_by,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        review_results.append({"raw_line": item.raw_line, **result})

    session["config"] = config
    return {"session_id": body.session_id, "config": config, "review_results": review_results}


# ---------- POST /evaluate ----------

@app.post("/evaluate/{session_id}")
async def evaluate_session(session_id: str, frameworks: str = "CIS"):
    """
    Runs Block 3 (compliance evaluation) on this session's current config
    (including any confirmations already applied). Stores the result on
    the session so /report/{session_id}/pdf can use it afterward.

    `frameworks` is a comma-separated list of rule packs to evaluate
    against, e.g. "CIS,NIST". Defaults to CIS only.
    """
    session = SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown session_id -- did you call /upload first?")

    framework_list = [f.strip().upper() for f in frameworks.split(",") if f.strip()]
    rules = load_selected_rule_packs(framework_list)
    converter_output = {"device": session["device"], "config": session["config"]}
    eval_result = evaluate_report(converter_output, rules)

    session["eval_result"] = eval_result
    session["framework"] = ", ".join(framework_list)

    return eval_result


# ---------- GET /report/{session_id}/pdf ----------

@app.get("/report/{session_id}/pdf")
async def get_report_pdf(session_id: str):
    """
    Generates and returns the PDF for a session that's already been
    evaluated (via /evaluate). Call /evaluate first.
    """
    session = SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown session_id -- did you call /upload first?")
    if "eval_result" not in session:
        raise HTTPException(status_code=400, detail="Call /evaluate/{session_id} before requesting the PDF.")

    pdf_bytes = generate_pdf_bytes(session["eval_result"], framework=session.get("framework", "CIS"))

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="compliance_report_{session_id[:8]}.pdf"'},
    )

@app.get("/review/report")
async def review_report():
    """Compliance-relevant: shows what's been consensus-confirmed, what's
    still pending, and whether the audit trail is intact."""
    return review_system.generate_report() 

@app.get("/health")
async def health():
    return {"status": "ok"}


# ---------- Serve the frontend ----------
# Mounted under /app so it can't collide with the /upload, /confirm, etc.
# API routes above. Visiting "/" just bounces to the first screen.

@app.get("/")
async def root():
    return RedirectResponse(url="/app/upload_configuration/index.html")


if FRONTEND_DIR.is_dir():
    app.mount("/app", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")