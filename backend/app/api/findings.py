from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.models import Finding, Evidence
from app.schemas.schemas import FindingResponse, EvidenceItemResponse

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("", response_model=list[FindingResponse])
def list_findings(
    severity: str = Query(None),
    category: str = Query(None),
    evidence_type: str = Query(None),
    capture_id: str = Query(None),
    search: str = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(Finding)
    if severity:
        query = query.filter(Finding.severity.ilike(severity))
    if category:
        query = query.filter(Finding.category.ilike(category))
    if evidence_type:
        query = query.filter(Finding.evidence_type.ilike(evidence_type))
    if capture_id:
        query = query.filter(Finding.capture_id == capture_id)
    if search:
        query = query.filter(
            (Finding.title.ilike(f"%{search}%")) |
            (Finding.rule_id.ilike(f"%{search}%")) |
            (Finding.standards_reference.ilike(f"%{search}%"))
        )

    findings = query.all()
    # Sort with custom priority: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    findings.sort(key=lambda f: order.get(f.severity.upper(), 5))
    return findings

@router.get("/{id}", response_model=FindingResponse)
def get_finding(id: str, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f
