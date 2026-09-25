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

Auth (Phase 1): every endpoint except /health, /auth/signup and
/auth/login requires `Authorization: Bearer <token>`. See
docs/auth_decisions.md and the auth/ package.

Roles (Phase 4): every endpoint below also declares the Permission it needs
via require_permission(...). A signed-in caller whose role lacks it gets 403
before anything else happens. When you add an endpoint, give it one --
auth/test_rbac.py fails if a route has neither a permission nor an entry in
its list of deliberately-open routes.

Tenant isolation (Phase 2): every session is stamped with the uploader's
org_id, and every endpoint that takes a session_id MUST fetch it through
_get_session_for(session_id, user) -- never SESSIONS.get() directly. A
session from another org gets exactly the same 404 as one that doesn't
exist, so responses never reveal which session ids are real.
"""

import os
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import activity_log
from pipeline import apply_confirmation, process_config
from shared.schema import NormalizedConfig
from compliance_engine.evaluator import FRAMEWORK_FILE_MAP, evaluate_report, load_selected_rule_packs
from report_generator.report_gen import generate_pdf_bytes
from auth import store as auth_store
from auth.admin_routes import router as admin_router
from auth.config import Permission, get_jwt_secret
from auth.deps import require_permission
from auth.routes import router as auth_router
from auth.store import User
from block2b import memory, review_system

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"

app = FastAPI(title="Network Compliance Engine API")

# ---------- Startup: tables + demo accounts ----------
# Refuse to start without a usable JWT_SECRET rather than fail on first login.
get_jwt_secret()

# Order matters: auth owns the `users` table that review_system reads.
memory.init_db()
auth_store.init_auth_tables()
review_system.init_review_tables()
activity_log.init_activity_log_table()

_demo_password = os.getenv("DEMO_PASSWORD", "")
if len(_demo_password) >= 10:
    auth_store.seed_demo_accounts(_demo_password)
else:
    print("[auth] DEMO_PASSWORD not set (or under 10 chars) in .env -- demo accounts not seeded.")

app.include_router(auth_router)
app.include_router(admin_router)

# Allow the frontend, and only the frontend, to call this API. Origins
# come from FRONTEND_ORIGINS in .env (comma-separated, same pattern as
# every other env-driven setting in auth/config.py), falling back to
# where README.md says to actually run it during development
# (`cd src/frontend && python3 -m http.server 5500`). allow_credentials
# stays off: auth is a Bearer token in the Authorization header, never a
# cookie (see auth/deps.py), so there's nothing for it to cover.
_DEFAULT_FRONTEND_ORIGINS = "http://localhost:5500,http://127.0.0.1:5500"
_frontend_origins = [
    origin.strip()
    for origin in os.getenv("FRONTEND_ORIGINS", _DEFAULT_FRONTEND_ORIGINS).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_frontend_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Upload limits: the whole file is read into memory and every line goes
# through the parser (and possibly the LLM), so unbounded uploads are a
# cheap way to knock the server over.
MAX_UPLOAD_FILES = 20
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # per file (the upload page promises 10 MB)

# In-memory session store: session_id -> {"org_id": ..., "owner_id": ...,
# "filename": ..., "raw_text": ..., "device": ..., "config": ...}
SESSIONS: dict[str, dict] = {}

SESSION_NOT_FOUND = "Unknown session_id -- did you call /upload first?"


def _get_session_for(session_id: str, user: User) -> dict:
    """The one place session ownership is checked. Any member of the
    uploader's org may use the session (teammates review each other's
    scans); nobody outside it can tell the session exists."""
    session = SESSIONS.get(session_id)
    if session is None or session.get("org_id") != user.org_id:
        raise HTTPException(status_code=404, detail=SESSION_NOT_FOUND)
    return session


# ---------- POST /upload ----------

@app.post("/upload")
async def upload_configs(
    files: list[UploadFile] = File(...),
    vendor_hint: str | None = Form(default=None),
    user: User = Depends(require_permission(Permission.UPLOAD)),
):
    """
    Accepts one or more config files (bulk upload supported, per the
    problem statement's "single or bulk configuration files" requirement).
    Runs Block 2 (detection + parsing + LLM fallback) on each file
    independently and returns one result per file, each with its own
    session_id for the frontend to reference in later calls.
    """
    if len(files) > MAX_UPLOAD_FILES:
        raise HTTPException(
            status_code=413,
            detail=f"Too many files: upload at most {MAX_UPLOAD_FILES} at a time.",
        )

    results = []
    for upload in files:
        # Read one byte past the limit so an oversized file is detected
        # without ever holding more than that in memory.
        raw_bytes = await upload.read(MAX_UPLOAD_BYTES + 1)
        if len(raw_bytes) > MAX_UPLOAD_BYTES:
            results.append({
                "filename": upload.filename,
                "error": f"File is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB -- not a plain-text config export.",
            })
            activity_log.log_event(user, "upload_rejected", target=upload.filename,
                                    detail={"reason": "too_large"})
            continue
        try:
            # utf-8-sig: Windows editors often prepend a BOM, which would
            # otherwise stick to the first line and break its parser match.
            raw_text = raw_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            results.append({
                "filename": upload.filename,
                "error": "File is not valid UTF-8 text -- check it's a plain-text config export.",
            })
            activity_log.log_event(user, "upload_rejected", target=upload.filename,
                                    detail={"reason": "not_utf8"})
            continue

        result = process_config(raw_text, user_declared_vendor=vendor_hint, org_id=user.org_id)

        session_id = str(uuid.uuid4())
        SESSIONS[session_id] = {
            # Stamped from the token, never from the request.
            "org_id": user.org_id,
            "owner_id": user.user_id,
            "filename": upload.filename,
            "raw_text": raw_text,
            "device": result["device"],
            "config": result["config"],
        }
        activity_log.log_event(user, "upload", target=session_id,
                                detail={"filename": upload.filename, "vendor": result["device"].get("vendor")})

        results.append({
            "session_id": session_id,
            "filename": upload.filename,
            "device": result["device"],
            "config": result["config"],
            "pending_confirmations": result["pending_confirmations"],
        })

    return {"results": results}


# ---------- POST /confirm ----------

# A reviewer can only vote for a field the schema actually has (or "unclear").
# Without this, a typo or a hostile client could promote an arbitrary key into
# the org's permanent learned-line memory.
CONFIRMABLE_FIELDS = set(NormalizedConfig.model_fields) | {"unclear"}


class ConfirmationItem(BaseModel):
    raw_line: str
    field: str
    value: object = None


class ConfirmRequest(BaseModel):
    session_id: str
    confirmations: list[ConfirmationItem]
    # No confirmed_by: the reviewer is whoever the access token belongs to.
    # Old clients that still send it are ignored (pydantic drops extra keys).


@app.post("/confirm")
async def confirm_lines(body: ConfirmRequest, user: User = Depends(require_permission(Permission.CONFIRM))):
    """
    Accepts a batch of human-confirmed/corrected classifications from the
    review-unknown-lines screen. Saves each to memory (so it's recognized
    instantly next time) and merges resolved fields into this session's
    config.
    """
    session = _get_session_for(body.session_id, user)

    # Validate the whole batch first so a bad item can't leave the earlier
    # ones already voted on.
    for item in body.confirmations:
        if item.field not in CONFIRMABLE_FIELDS:
            raise HTTPException(status_code=400, detail=f"Unknown field {item.field!r}.")

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
                confirmed_by=user.user_id,
                org_id=user.org_id,
            )
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        review_results.append({"raw_line": item.raw_line, **result})
        activity_log.log_event(user, "confirm", target=body.session_id,
                                detail={"field": item.field, "status": result.get("status")})
        # Saved per item, not once after the loop: votes are already
        # committed to the database, so if a later item in the batch fails
        # the lines that DID reach consensus must not be lost from the session.
        session["config"] = config

    return {"session_id": body.session_id, "config": config, "review_results": review_results}


# ---------- POST /evaluate ----------

@app.post("/evaluate/{session_id}")
async def evaluate_session(
    session_id: str,
    frameworks: str = "CIS",
    user: User = Depends(require_permission(Permission.EVALUATE)),
):
    """
    Runs Block 3 (compliance evaluation) on this session's current config
    (including any confirmations already applied). Stores the result on
    the session so /report/{session_id}/pdf can use it afterward.

    `frameworks` is a comma-separated list of rule packs to evaluate
    against, e.g. "CIS,NIST". Defaults to CIS only.
    """
    session = _get_session_for(session_id, user)

    framework_list = [f.strip().upper() for f in frameworks.split(",") if f.strip()] or ["CIS"]
    unknown = [f for f in framework_list if f not in FRAMEWORK_FILE_MAP]
    if unknown:
        # Previously unknown names were skipped silently, which produced an
        # empty report that looked like a clean bill of health.
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework(s): {', '.join(unknown)}. Choose from: {', '.join(FRAMEWORK_FILE_MAP)}.",
        )
    rules = load_selected_rule_packs(framework_list)
    converter_output = {"device": session["device"], "config": session["config"]}
    eval_result = evaluate_report(converter_output, rules)

    session["eval_result"] = eval_result
    session["framework"] = ", ".join(framework_list)
    activity_log.log_event(user, "evaluate", target=session_id, detail={"frameworks": framework_list})

    return eval_result


# ---------- GET /report/{session_id}/pdf ----------

@app.get("/report/{session_id}/pdf")
async def get_report_pdf(session_id: str, user: User = Depends(require_permission(Permission.VIEW_REPORTS))):
    """
    Generates and returns the PDF for a session that's already been
    evaluated (via /evaluate). Call /evaluate first.
    """
    session = _get_session_for(session_id, user)
    if "eval_result" not in session:
        raise HTTPException(status_code=400, detail="Call /evaluate/{session_id} before requesting the PDF.")

    try:
        pdf_bytes = generate_pdf_bytes(session["eval_result"], framework=session.get("framework", "CIS"))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    activity_log.log_event(user, "report_pdf_download", target=session_id)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="compliance_report_{session_id[:8]}.pdf"'},
    )


# ---------- GET /sessions ----------

@app.get("/sessions")
async def list_sessions(user: User = Depends(require_permission(Permission.VIEW_REPORTS))):
    """
    Session discovery (Phase 6): a viewer has VIEW_REPORTS but, before
    this, no way to learn a session_id short of being handed one --
    they could read /review/report and, given an id, download its PDF,
    but couldn't find that id themselves. Scoped to the caller's org_id
    exactly the way _get_session_for() scopes single-session access, so
    this can't be used to enumerate another org's sessions. Returns only
    session_id, filename and whether it's been evaluated -- never
    raw_text, device or config.

    Not logged: like GET /audit, this lists metadata about what exists
    rather than returning report content, so it follows the pattern of
    the reads that aren't logged (GET /audit itself) rather than the
    reads that are (report_pdf_download, an actual export). Note the
    latter is the only GET currently logged -- /review/report is not,
    despite also returning compliance-relevant content -- so "not logged"
    is the safer default for another metadata-only GET.
    """
    return {
        "sessions": [
            {
                "session_id": session_id,
                "filename": session["filename"],
                "evaluated": "eval_result" in session,
            }
            for session_id, session in SESSIONS.items()
            if session["org_id"] == user.org_id
        ]
    }


@app.get("/review/report")
async def review_report(user: User = Depends(require_permission(Permission.VIEW_REPORTS))):
    """Compliance-relevant: shows what's been consensus-confirmed, what's
    still pending, and whether the audit trail is intact -- for the
    caller's own organization only."""
    return review_system.generate_report(user.org_id)


@app.get("/audit")
async def get_activity_log(
    limit: int = 50,
    before_id: int | None = None,
    user: User = Depends(require_permission(Permission.VIEW_AUDIT_LOG)),
):
    """Paginated activity log for the caller's own organization (Phase 5),
    newest first, plus whether its hash chain is intact. Pass the previous
    response's next_before_id back in as before_id to page further back."""
    page = activity_log.list_activity_log(user.org_id, limit=limit, before_id=before_id)
    page["chain_valid"] = activity_log.verify_activity_chain(user.org_id)
    return page


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