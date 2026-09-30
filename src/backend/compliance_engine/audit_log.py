"""Append-only SQLite audit log for compliance scans.

Application code only INSERTs. Hash-chaining (prev_row_hash -> row_hash)
makes later edits to historical rows detectable via verify_audit_chain().
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "audit_log.db"

# Concatenation order for row_hash. Changing this breaks chain verification.
_HASH_FIELD_ORDER = (
    "timestamp_utc",
    "session_id",
    "vendor",
    "frameworks_used",
    "raw_file_hash",
    "config_hash",
    "parser_warnings",
    "pass_count",
    "fail_count",
    "not_evaluated_count",
    "prev_row_hash",
)

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    session_id TEXT,
    vendor TEXT,
    frameworks_used TEXT NOT NULL,
    raw_file_hash TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    parser_warnings TEXT,
    pass_count INTEGER,
    fail_count INTEGER,
    not_evaluated_count INTEGER,
    prev_row_hash TEXT,
    row_hash TEXT NOT NULL
)
"""


def _resolve_db_path(db_path: str | Path | None) -> str:
    if db_path is None:
        return str(DEFAULT_DB_PATH)
    return str(db_path)


def _connect(db_path: str | Path | None) -> sqlite3.Connection:
    conn = sqlite3.connect(_resolve_db_path(db_path), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_audit_db(db_path: str | Path = "audit_log.db") -> None:
    path = DEFAULT_DB_PATH if db_path == "audit_log.db" else db_path
    conn = _connect(path)
    try:
        conn.execute(_CREATE_SQL)
        conn.commit()
    finally:
        conn.close()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _hash_join(values: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in _HASH_FIELD_ORDER:
        val = values.get(key)
        if val is None:
            parts.append("")
        else:
            parts.append(str(val))
    return _sha256_text("|".join(parts))


def _count_statuses(findings: list[dict[str, Any]]) -> tuple[int, int, int]:
    pass_count = fail_count = not_evaluated_count = 0
    for finding in findings:
        status = finding.get("status")
        if status == "PASS":
            pass_count += 1
        elif status == "FAIL":
            fail_count += 1
        elif status == "NOT_EVALUATED":
            not_evaluated_count += 1
    return pass_count, fail_count, not_evaluated_count


def _normalize_warnings(parser_warnings: Any) -> str | None:
    if parser_warnings is None:
        return None
    if isinstance(parser_warnings, str):
        text = parser_warnings.strip()
        return text or None
    if isinstance(parser_warnings, (list, tuple)):
        parts = [str(item).strip() for item in parser_warnings if str(item).strip()]
        return ",".join(parts) if parts else None
    text = str(parser_warnings).strip()
    return text or None


def _frameworks_csv(frameworks_used: Any) -> str:
    if isinstance(frameworks_used, str):
        return ",".join(part.strip() for part in frameworks_used.split(",") if part.strip())
    if isinstance(frameworks_used, (list, tuple)):
        return ",".join(str(item).strip() for item in frameworks_used if str(item).strip())
    return str(frameworks_used)


def _latest_row_hash(conn: sqlite3.Connection) -> str | None:
    row = conn.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    if row is None:
        return None
    return row["row_hash"]


def log_scan_event(
    raw_file_bytes: bytes,
    converter_output_json: dict[str, Any],
    result: dict[str, Any],
    frameworks_used: Any,
    session_id: str | None = None,
    parser_warnings: Any = None,
    db_path: str | Path = "audit_log.db",
) -> None:
    """Insert one append-only audit row. Never reads claimed vendor/timestamp/session from config."""
    init_audit_db(db_path)

    if not isinstance(raw_file_bytes, (bytes, bytearray)):
        raise TypeError("raw_file_bytes must be the uploaded file bytes")

    raw_file_hash = _sha256_bytes(bytes(raw_file_bytes))

    # Config payload only — never hash claimed audit metadata as the evaluated config.
    config_obj = {}
    if isinstance(converter_output_json, dict):
        maybe_config = converter_output_json.get("config", {})
        if isinstance(maybe_config, dict):
            config_obj = maybe_config
    config_hash = _sha256_text(json.dumps(config_obj, sort_keys=True))

    timestamp_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Vendor comes from the detector's device record, never config["vendor"].
    vendor = None
    if isinstance(converter_output_json, dict):
        device = converter_output_json.get("device")
        if isinstance(device, dict):
            detected = device.get("vendor")
            if detected is not None and str(detected).strip():
                vendor = str(detected).strip()

    frameworks_csv = _frameworks_csv(frameworks_used)
    warnings_csv = _normalize_warnings(parser_warnings)
    pass_count, fail_count, not_evaluated_count = _count_statuses(result.get("findings") or [])

    path = DEFAULT_DB_PATH if db_path == "audit_log.db" else db_path
    conn = _connect(path)
    try:
        prev_row_hash = _latest_row_hash(conn)
        payload = {
            "timestamp_utc": timestamp_utc,
            "session_id": session_id,
            "vendor": vendor,
            "frameworks_used": frameworks_csv,
            "raw_file_hash": raw_file_hash,
            "config_hash": config_hash,
            "parser_warnings": warnings_csv,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "not_evaluated_count": not_evaluated_count,
            "prev_row_hash": prev_row_hash,
        }
        row_hash = _hash_join(payload)
        conn.execute(
            """
            INSERT INTO audit_log (
                timestamp_utc, session_id, vendor, frameworks_used,
                raw_file_hash, config_hash, parser_warnings,
                pass_count, fail_count, not_evaluated_count,
                prev_row_hash, row_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp_utc,
                session_id,
                vendor,
                frameworks_csv,
                raw_file_hash,
                config_hash,
                warnings_csv,
                pass_count,
                fail_count,
                not_evaluated_count,
                prev_row_hash,
                row_hash,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def query_audit_log(db_path: str | Path = "audit_log.db", limit: int = 50) -> list[dict[str, Any]]:
    init_audit_db(db_path)
    path = DEFAULT_DB_PATH if db_path == "audit_log.db" else db_path
    conn = _connect(path)
    try:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def verify_audit_chain(db_path: str | Path = "audit_log.db") -> tuple[bool, int | None]:
    init_audit_db(db_path)
    path = DEFAULT_DB_PATH if db_path == "audit_log.db" else db_path
    conn = _connect(path)
    try:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    finally:
        conn.close()

    previous_hash: str | None = None
    for row in rows:
        stored_prev = row["prev_row_hash"]
        if stored_prev != previous_hash:
            return False, row["id"]
        payload = {
            "timestamp_utc": row["timestamp_utc"],
            "session_id": row["session_id"],
            "vendor": row["vendor"],
            "frameworks_used": row["frameworks_used"],
            "raw_file_hash": row["raw_file_hash"],
            "config_hash": row["config_hash"],
            "parser_warnings": row["parser_warnings"],
            "pass_count": row["pass_count"],
            "fail_count": row["fail_count"],
            "not_evaluated_count": row["not_evaluated_count"],
            "prev_row_hash": stored_prev,
        }
        recomputed = _hash_join(payload)
        if recomputed != row["row_hash"]:
            return False, row["id"]
        previous_hash = row["row_hash"]
    return True, None
