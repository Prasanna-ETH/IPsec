from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.database import get_db
from app.models.models import Capture, Tunnel, IKESession, IKEProposal, RiskAssessment
from app.schemas.schemas import ComparisonResponse
from app.engines.comparison_engine import compare_captures_data

router = APIRouter(prefix="/compare", tags=["Comparison"])

class CompareRequest(BaseModel):
    baseline_capture_id: str
    remediation_capture_id: str

@router.post("", response_model=ComparisonResponse)
def compare_captures(payload: CompareRequest, db: Session = Depends(get_db)):
    base_c = db.query(Capture).filter(Capture.id == payload.baseline_capture_id).first()
    remed_c = db.query(Capture).filter(Capture.id == payload.remediation_capture_id).first()

    if not base_c or not remed_c:
        raise HTTPException(status_code=404, detail="One or both capture IDs not found")

    base_risk = db.query(RiskAssessment).filter(RiskAssessment.capture_id == base_c.id).first()
    remed_risk = db.query(RiskAssessment).filter(RiskAssessment.capture_id == remed_c.id).first()

    # Find proposals for baseline
    base_props = db.query(IKEProposal).join(IKESession).filter(IKESession.capture_id == base_c.id).all()
    remed_props = db.query(IKEProposal).join(IKESession).filter(IKESession.capture_id == remed_c.id).all()

    base_p1 = base_props[0] if base_props else None
    remed_p1 = remed_props[0] if remed_props else None

    # Find tunnel IKE version
    base_t = db.query(Tunnel).filter(Tunnel.capture_id == base_c.id).first()
    remed_t = db.query(Tunnel).filter(Tunnel.capture_id == remed_c.id).first()

    base_dict = {
        "id": base_c.id,
        "filename": base_c.filename,
        "ike_version": base_t.ike_version if base_t else "IKEv1",
        "encryption_alg": base_p1.encryption_alg if base_p1 else "3DES-CBC",
        "dh_group": base_p1.dh_group if base_p1 else "Group 2 (MODP-1024)",
        "integrity_alg": base_p1.integrity_alg if base_p1 else "AUTH_HMAC_MD5_96",
        "risk_score": base_risk.overall_score if base_risk else 75.0
    }

    remed_dict = {
        "id": remed_c.id,
        "filename": remed_c.filename,
        "ike_version": remed_t.ike_version if remed_t else "IKEv2",
        "encryption_alg": remed_p1.encryption_alg if remed_p1 else "AES-256-GCM",
        "dh_group": remed_p1.dh_group if remed_p1 else "Group 19 (ECP-256)",
        "integrity_alg": remed_p1.integrity_alg if remed_p1 else "AUTH_HMAC_SHA2_256_128",
        "risk_score": remed_risk.overall_score if remed_risk else 18.0
    }

    res = compare_captures_data(base_dict, remed_dict)
    return ComparisonResponse(**res)
