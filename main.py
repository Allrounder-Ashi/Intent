"""
Person 4: Backend & Integration Layer
----------------------------------------
FastAPI app exposing:
  Citizen side:
    POST /api/report   - submit evidence (audio/images/text), runs full pipeline, stores + returns verdict
    GET  /api/search    - check if a phone/UPI/URL/email has been reported before

  Agency side (require header  X-Agency-Key: <AGENCY_ACCESS_CODE>):
    GET   /api/stats            - dashboard overview numbers
    GET   /api/cases            - list all reports (filter by status/risk)
    GET   /api/cases/{id}       - full case detail
    PATCH /api/cases/{id}       - update status / add investigator notes

Run locally:
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000
"""
import json
import os
import shutil
import tempfile
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import or_

from database import init_db, get_db, Report, ReportedIdentifier, AuditLog, ReportStatus
from pipeline import run_full_pipeline
from metadata_extractor import extract_metadata
from person3_security import report_scam_identifier

AGENCY_ACCESS_CODE = os.environ.get("AGENCY_ACCESS_CODE", "changeme-demo-key")

app = FastAPI(title="ProtectX API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before real deployment
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


def require_agency(x_agency_key: Optional[str] = Header(default=None)):
    if x_agency_key != AGENCY_ACCESS_CODE:
        raise HTTPException(status_code=401, detail="Invalid or missing agency access key")
    return True


def _upsert_identifier(db: Session, identifier: str, identifier_type: str, risk_label: str):
    if not identifier:
        return
    row = db.query(ReportedIdentifier).filter_by(identifier=identifier).first()
    rank = {"low": 0, "medium": 1, "high": 2}
    if row:
        row.report_count += 1
        if rank.get(risk_label, 0) > rank.get(row.max_risk_label, 0):
            row.max_risk_label = risk_label
        import datetime
        row.last_reported_at = datetime.datetime.utcnow()
    else:
        row = ReportedIdentifier(
            identifier=identifier, identifier_type=identifier_type,
            report_count=1, max_risk_label=risk_label,
        )
        db.add(row)


# ---------------------------------------------------------------------------
# CITIZEN ENDPOINTS
# ---------------------------------------------------------------------------
@app.post("/api/report")
async def submit_report(
    phone_number: Optional[str] = Form(None),
    upi_id: Optional[str] = Form(None),
    reported_url: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    call_transcript_text: Optional[str] = Form(None),
    sms_text: Optional[str] = Form(None),
    other_details: Optional[str] = Form(None),
    audio: Optional[UploadFile] = File(None),
    screenshots: list[UploadFile] = File(default=[]),
    db: Session = Depends(get_db),
):
    tmp_dir = tempfile.mkdtemp(prefix="protectx_")
    audio_path = None
    image_paths = []
    try:
        if audio is not None:
            audio_path = os.path.join(tmp_dir, audio.filename)
            with open(audio_path, "wb") as f:
                shutil.copyfileobj(audio.file, f)

        for img in screenshots:
            img_path = os.path.join(tmp_dir, img.filename)
            with open(img_path, "wb") as f:
                shutil.copyfileobj(img.file, f)
            image_paths.append(img_path)

        result = run_full_pipeline(
            audio_path=audio_path,
            image_paths=image_paths or None,
            raw_text_override=call_transcript_text,
            sms_text=sms_text,
            phone_number=phone_number,
            upi_id=upi_id,
            reported_url=reported_url,
            email=email,
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    risk = result["risk_assessment"]

    report = Report(
        phone_number=phone_number,
        upi_id=upi_id,
        reported_url=reported_url,
        email=email,
        transcript_text=result["transcript"]["clean_text"],
        sms_text=sms_text,
        ocr_text=result["ocr_text"],
        other_details=other_details,
        extracted_metadata_json=json.dumps(result["extracted_metadata"]),
        ai_analysis_json=json.dumps(result["ai_analysis"]),
        security_check_json=json.dumps(result["security_check"]),
        risk_score=risk["risk_score"],
        risk_label=risk["risk_label"],
        risk_confidence=risk["confidence"],
        risk_reasoning_json=json.dumps(risk["reasoning"]),
        is_scam=risk["is_scam"],
        status=ReportStatus.new,
    )
    db.add(report)
    db.flush()

    for identifier, itype in [
        (phone_number, "phone"), (upi_id, "upi"),
        (reported_url, "url"), (email, "email"),
    ]:
        _upsert_identifier(db, identifier, itype, risk["risk_label"])

    # Keep Person 3's own scam DB in sync too, but only for confirmed-risky
    # reports (not every lookup) so a low-risk submission doesn't wrongly
    # "convict" a number/UPI/URL.
    if risk["is_scam"]:
        for identifier, itype in [
            (phone_number, "phone"), (upi_id, "upi"), (reported_url, "url"),
        ]:
            if identifier:
                report_scam_identifier(identifier, identifier_type=itype)

    db.add(AuditLog(actor="citizen", action="report_submitted", report_id=report.id))
    db.commit()
    db.refresh(report)

    return {
        "report_id": report.id,
        "risk_label": risk["risk_label"],
        "risk_score": risk["risk_score"],
        "confidence": risk["confidence"],
        "is_scam": risk["is_scam"],
        "reasoning": risk["reasoning"],
        "scam_type": result["ai_analysis"].get("scam_type"),
        "tactics_used": result["ai_analysis"].get("tactics_used"),
        "ai_analysis": result["ai_analysis"],
        "security_check": result["security_check"],
        "extracted_metadata": result["extracted_metadata"],
    }


@app.get("/api/search")
def search_identifier(query: str, db: Session = Depends(get_db)):
    row = db.query(ReportedIdentifier).filter(ReportedIdentifier.identifier == query).first()
    matching_reports = (
        db.query(Report)
        .filter(
            or_(
                Report.phone_number == query,
                Report.upi_id == query,
                Report.reported_url == query,
                Report.email == query,
            )
        )
        .order_by(Report.created_at.desc())
        .limit(10)
        .all()
    )
    db.add(AuditLog(actor="citizen", action="search", detail=query))
    db.commit()

    if not row and not matching_reports:
        return {"found": False, "message": "No prior reports found for this identifier."}

    return {
        "found": True,
        "identifier": query,
        "report_count": row.report_count if row else len(matching_reports),
        "max_risk_label": row.max_risk_label if row else None,
        "recent_reports": [
            {
                "id": r.id,
                "created_at": r.created_at.isoformat(),
                "risk_label": r.risk_label,
                "risk_score": r.risk_score,
            }
            for r in matching_reports
        ],
    }


# ---------------------------------------------------------------------------
# AGENCY ENDPOINTS (require X-Agency-Key header)
# ---------------------------------------------------------------------------
@app.get("/api/stats")
def dashboard_stats(db: Session = Depends(get_db), _=Depends(require_agency)):
    total = db.query(Report).count()
    high_risk = db.query(Report).filter(Report.risk_label == "high").count()
    new = db.query(Report).filter(Report.status == ReportStatus.new).count()
    resolved = db.query(Report).filter(Report.status == ReportStatus.resolved).count()
    return {"total_reports": total, "high_risk_cases": high_risk, "new": new, "resolved": resolved}


@app.get("/api/cases")
def list_cases(
    status: Optional[str] = None,
    risk_label: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(require_agency),
):
    q = db.query(Report)
    if status:
        q = q.filter(Report.status == status)
    if risk_label:
        q = q.filter(Report.risk_label == risk_label)
    reports = q.order_by(Report.created_at.desc()).limit(200).all()
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat(),
            "phone_number": r.phone_number,
            "upi_id": r.upi_id,
            "reported_url": r.reported_url,
            "risk_label": r.risk_label,
            "risk_score": r.risk_score,
            "status": r.status,
        }
        for r in reports
    ]


@app.get("/api/cases/{case_id}")
def case_detail(case_id: int, db: Session = Depends(get_db), _=Depends(require_agency)):
    r = db.query(Report).filter(Report.id == case_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Case not found")
    return {
        "id": r.id,
        "created_at": r.created_at.isoformat(),
        "phone_number": r.phone_number,
        "upi_id": r.upi_id,
        "reported_url": r.reported_url,
        "email": r.email,
        "transcript_text": r.transcript_text,
        "sms_text": r.sms_text,
        "ocr_text": r.ocr_text,
        "other_details": r.other_details,
        "extracted_metadata": json.loads(r.extracted_metadata_json or "{}"),
        "ai_analysis": json.loads(r.ai_analysis_json or "{}"),
        "security_check": json.loads(r.security_check_json or "{}"),
        "risk_score": r.risk_score,
        "risk_label": r.risk_label,
        "risk_confidence": r.risk_confidence,
        "risk_reasoning": json.loads(r.risk_reasoning_json or "[]"),
        "is_scam": r.is_scam,
        "status": r.status,
        "agency_notes": r.agency_notes,
    }


@app.patch("/api/cases/{case_id}")
def update_case(
    case_id: int,
    status: Optional[str] = Form(None),
    agency_notes: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _=Depends(require_agency),
):
    r = db.query(Report).filter(Report.id == case_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Case not found")
    if status:
        r.status = status
    if agency_notes is not None:
        r.agency_notes = agency_notes
    db.add(AuditLog(actor="agency", action="case_updated", report_id=case_id, detail=status or ""))
    db.commit()
    return {"ok": True}


@app.get("/")
def root():
    return {"service": "ProtectX API", "status": "ok"}
