from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from .report_gen import generate_pdf_bytes

router = APIRouter(prefix="/api/reports", tags=["Report Generation"])

class ReportRequest(BaseModel):
    device: Optional[Dict[str, Any]] = {}
    findings: List[Dict[str, Any]]
    warning: Optional[str] = None
    framework: Optional[str] = "CIS Baseline"

@router.post("/pdf")
async def download_pdf_report(payload: ReportRequest):
    """
    Receives JSON evaluation payload from Block 3, compiles PDF in memory,
    and returns a downloadable file stream to Block 1 (Frontend).
    """
    try:
        raw_dict = payload.model_dump()
        pdf_bytes = generate_pdf_bytes(raw_dict, framework=payload.framework)
        
        hostname = raw_dict.get("device", {}).get("hostname", "network_device")
        filename = f"Compliance_Report_{hostname}.pdf"
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Generation failed: {str(e)}")