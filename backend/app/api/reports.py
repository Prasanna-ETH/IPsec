import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.models import Capture, Tunnel, Finding, RiskAssessment, Report
from app.core.config import settings
from app.reports.pdf_report import generate_pdf_report
from app.reports.json_report import generate_json_report

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.post("/{capture_id}")
def create_report(
    capture_id: str,
    report_type: str = "PDF",  # PDF or JSON
    db: Session = Depends(get_db)
):
    c = db.query(Capture).filter(Capture.id == capture_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Capture not found")

    tunnels = db.query(Tunnel).filter(Tunnel.capture_id == capture_id).all()
    findings = db.query(Finding).filter(Finding.capture_id == capture_id).all()
    risk = db.query(RiskAssessment).filter(RiskAssessment.capture_id == capture_id).first()

    capture_data = {
        "filename": c.filename,
        "sha256": c.sha256,
        "packet_count": c.packet_count,
        "ike_packet_count": c.ike_packet_count,
        "esp_packet_count": c.esp_packet_count,
        "natt_packet_count": c.natt_packet_count,
        "other_packet_count": c.other_packet_count,
        "status": c.status,
    }

    tunnels_data = [
        {
            "id": t.id,
            "tunnel_key": t.tunnel_key,
            "endpoint_a": t.endpoint_a,
            "endpoint_b": t.endpoint_b,
            "ike_version": t.ike_version,
            "risk_score": t.risk_score,
            "risk_level": t.risk_level
        } for t in tunnels
    ]

    findings_data = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "evidence_type": f.evidence_type,
            "standards_reference": f.standards_reference,
            "technical_evidence": f.technical_evidence,
            "recommendation": f.recommendation,
            "confidence": f.confidence
        } for f in findings
    ]

    risk_data = {
        "overall_score": risk.overall_score if risk else 0.0,
        "risk_level": risk.risk_level if risk else "INFORMATIONAL",
        "crypto_score": risk.crypto_score if risk else 0.0,
        "key_mgmt_score": risk.key_mgmt_score if risk else 0.0,
        "protocol_score": risk.protocol_score if risk else 0.0,
        "anomaly_score": risk.anomaly_score if risk else 0.0,
        "metadata_score": risk.metadata_score if risk else 0.0,
    }

    fmt = report_type.upper()
    timestamp_str = int(datetime.utcnow().timestamp())

    if fmt == "PDF":
        filename = f"OMEGA_Assessment_{c.filename}_{timestamp_str}.pdf"
        out_path = settings.REPORTS_DIR / filename
        sha256 = generate_pdf_report(capture_data, tunnels_data, findings_data, risk_data, out_path)
    elif fmt == "JSON":
        filename = f"OMEGA_Assessment_{c.filename}_{timestamp_str}.json"
        out_path = settings.REPORTS_DIR / filename
        sha256 = generate_json_report(capture_data, tunnels_data, findings_data, risk_data, out_path)
    else:
        raise HTTPException(status_code=400, detail="Invalid report format. Choose PDF or JSON.")

    report_rec = Report(
        capture_id=c.id,
        report_type=fmt,
        filename=filename,
        filepath=str(out_path),
        sha256=sha256
    )
    db.add(report_rec)
    db.commit()
    db.refresh(report_rec)

    return {
        "report_id": report_rec.id,
        "report_type": report_rec.report_type,
        "filename": report_rec.filename,
        "sha256": report_rec.sha256,
        "download_url": f"/api/v1/reports/{report_rec.id}/download"
    }

from datetime import datetime

@router.get("/{id}/download")
def download_report(id: str, db: Session = Depends(get_db)):
    r = db.query(Report).filter(Report.id == id).first()
    if not r or not os.path.exists(r.filepath):
        raise HTTPException(status_code=404, detail="Report file not found")

    media_type = "application/pdf" if r.report_type == "PDF" else "application/json"
    return FileResponse(
        r.filepath,
        media_type=media_type,
        filename=r.filename
    )

@router.get("", response_model=list[dict])
def list_reports(db: Session = Depends(get_db)):
    reports = db.query(Report).order_by(Report.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "capture_id": r.capture_id,
            "report_type": r.report_type,
            "filename": r.filename,
            "sha256": r.sha256,
            "created_at": r.created_at,
            "download_url": f"/api/v1/reports/{r.id}/download"
        } for r in reports
    ]
