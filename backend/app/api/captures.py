import os
import hashlib
import aiofiles
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks, Query
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.models import Capture, PacketMetadata, Tunnel, Finding, RiskAssessment
from app.schemas.schemas import (
    CaptureSummaryResponse, CaptureCreateResponse, PacketListResponse,
    PacketMetadataResponse, TunnelResponse, FindingResponse, RiskAssessmentResponse
)
from app.core.config import settings
from app.services.analysis_service import analysis_service

router = APIRouter(prefix="/captures", tags=["Captures"])

@router.post("", response_model=CaptureCreateResponse)
async def upload_capture(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Accepts PCAP/PCAPNG network capture, computes SHA-256, and launches analysis.
    """
    filename = file.filename or "capture.pcap"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in (".pcap", ".pcapng", ".cap"):
        raise HTTPException(status_code=400, detail="Unsupported capture format. Please upload .pcap or .pcapng files.")

    # Save to disk safely
    dest_path = settings.UPLOAD_DIR / f"{int(datetime.utcnow().timestamp())}_{filename}"
    sha256_hash = hashlib.sha256()
    file_size = 0

    async with aiofiles.open(dest_path, 'wb') as out_file:
        while content := await file.read(1024 * 1024):  # 1MB chunks
            file_size += len(content)
            sha256_hash.update(content)
            await out_file.write(content)

    sha256_hex = sha256_hash.hexdigest()

    capture = Capture(
        filename=filename,
        filepath=str(dest_path),
        file_size=file_size,
        sha256=sha256_hex,
        status="PENDING",
        stage_progress=0,
        current_stage="Queued for analysis"
    )
    db.add(capture)
    db.commit()
    db.refresh(capture)

    # Launch 12-stage analysis asynchronously
    background_tasks.add_task(analysis_service.process_capture, capture.id)

    return CaptureCreateResponse(
        id=capture.id,
        filename=capture.filename,
        file_size=capture.file_size,
        sha256=capture.sha256,
        status=capture.status,
        stage_progress=capture.stage_progress,
        current_stage=capture.current_stage,
        created_at=capture.created_at
    )

from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "sample_captures"

@router.post("/sample/{sample_name}", response_model=CaptureCreateResponse)
def load_sample_capture(
    sample_name: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    src_file = SAMPLE_DIR / f"{sample_name}.pcap"
    if not src_file.exists():
        src_file = SAMPLE_DIR / sample_name
    if not src_file.exists():
        raise HTTPException(status_code=404, detail=f"Sample capture '{sample_name}' not found in sample_captures/ directory.")

    with open(src_file, "rb") as f:
        content = f.read()
        sha256_hex = hashlib.sha256(content).hexdigest()
        file_size = len(content)

    dest_path = settings.UPLOAD_DIR / src_file.name
    with open(dest_path, "wb") as f:
        f.write(content)

    capture = Capture(
        filename=src_file.name,
        filepath=str(dest_path),
        file_size=file_size,
        sha256=sha256_hex,
        status="PENDING",
        stage_progress=0,
        current_stage="Queued for analysis"
    )
    db.add(capture)
    db.commit()
    db.refresh(capture)

    background_tasks.add_task(analysis_service.process_capture, capture.id)

    return CaptureCreateResponse(
        id=capture.id,
        filename=capture.filename,
        file_size=capture.file_size,
        sha256=capture.sha256,
        status=capture.status,
        stage_progress=capture.stage_progress,
        current_stage=capture.current_stage,
        created_at=capture.created_at
    )

from datetime import datetime

@router.get("", response_model=list[CaptureSummaryResponse])
def list_captures(db: Session = Depends(get_db)):
    """Lists all analyzed and active network captures."""
    captures = db.query(Capture).order_by(Capture.created_at.desc()).all()
    result = []
    for c in captures:
        t_count = db.query(Tunnel).filter(Tunnel.capture_id == c.id).count()
        f_count = db.query(Finding).filter(Finding.capture_id == c.id).count()
        risk = db.query(RiskAssessment).filter(RiskAssessment.capture_id == c.id).first()

        result.append(CaptureSummaryResponse(
            id=c.id,
            filename=c.filename,
            file_size=c.file_size,
            sha256=c.sha256,
            packet_count=c.packet_count,
            ike_packet_count=c.ike_packet_count,
            esp_packet_count=c.esp_packet_count,
            natt_packet_count=c.natt_packet_count,
            other_packet_count=c.other_packet_count,
            status=c.status,
            stage_progress=c.stage_progress,
            current_stage=c.current_stage,
            created_at=c.created_at,
            completed_at=c.completed_at,
            error_message=c.error_message,
            tunnels_count=t_count,
            findings_count=f_count,
            overall_risk_score=risk.overall_score if risk else 0.0,
            overall_risk_level=risk.risk_level if risk else "INFORMATIONAL"
        ))
    return result

@router.get("/{id}", response_model=CaptureSummaryResponse)
def get_capture(id: str, db: Session = Depends(get_db)):
    c = db.query(Capture).filter(Capture.id == id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Capture not found")
    t_count = db.query(Tunnel).filter(Tunnel.capture_id == c.id).count()
    f_count = db.query(Finding).filter(Finding.capture_id == c.id).count()
    risk = db.query(RiskAssessment).filter(RiskAssessment.capture_id == c.id).first()

    return CaptureSummaryResponse(
        id=c.id,
        filename=c.filename,
        file_size=c.file_size,
        sha256=c.sha256,
        packet_count=c.packet_count,
        ike_packet_count=c.ike_packet_count,
        esp_packet_count=c.esp_packet_count,
        natt_packet_count=c.natt_packet_count,
        other_packet_count=c.other_packet_count,
        status=c.status,
        stage_progress=c.stage_progress,
        current_stage=c.current_stage,
        created_at=c.created_at,
        completed_at=c.completed_at,
        error_message=c.error_message,
        tunnels_count=t_count,
        findings_count=f_count,
        overall_risk_score=risk.overall_score if risk else 0.0,
        overall_risk_level=risk.risk_level if risk else "INFORMATIONAL"
    )

@router.get("/{id}/status")
def get_capture_status(id: str, db: Session = Depends(get_db)):
    c = db.query(Capture).filter(Capture.id == id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Capture not found")
    return {
        "id": c.id,
        "status": c.status,
        "stage_progress": c.stage_progress,
        "current_stage": c.current_stage,
        "error_message": c.error_message,
        "completed_at": c.completed_at
    }

@router.get("/{id}/packets", response_model=PacketListResponse)
def get_capture_packets(
    id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    protocol: str = Query(None),
    is_ike: bool = Query(None),
    is_esp: bool = Query(None),
    is_natt: bool = Query(None),
    spi: str = Query(None),
    search: str = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(PacketMetadata).filter(PacketMetadata.capture_id == id)
    if protocol:
        query = query.filter(PacketMetadata.protocol.ilike(f"%{protocol}%"))
    if is_ike is not None:
        query = query.filter(PacketMetadata.is_ike == is_ike)
    if is_esp is not None:
        query = query.filter(PacketMetadata.is_esp == is_esp)
    if is_natt is not None:
        query = query.filter(PacketMetadata.is_natt == is_natt)
    if spi:
        query = query.filter(PacketMetadata.spi.ilike(f"%{spi}%"))
    if search:
        query = query.filter(
            (PacketMetadata.source_ip.ilike(f"%{search}%")) |
            (PacketMetadata.destination_ip.ilike(f"%{search}%")) |
            (PacketMetadata.summary.ilike(f"%{search}%"))
        )

    total = query.count()
    packets = query.order_by(PacketMetadata.frame_number.asc()).offset((page - 1) * page_size).limit(page_size).all()

    packet_items = [
        PacketMetadataResponse(
            id=p.id,
            frame_number=p.frame_number,
            timestamp=p.timestamp,
            source_ip=p.source_ip,
            destination_ip=p.destination_ip,
            source_port=p.source_port,
            destination_port=p.destination_port,
            protocol=p.protocol,
            length=p.length,
            summary=p.summary,
            is_ike=p.is_ike,
            is_esp=p.is_esp,
            is_natt=p.is_natt,
            spi=p.spi,
            raw_hex_preview=p.raw_hex_preview,
            detailed_json=p.detailed_json
        ) for p in packets
    ]

    return PacketListResponse(
        total=total,
        page=page,
        page_size=page_size,
        packets=packet_items
    )

@router.get("/{id}/tunnels", response_model=list[TunnelResponse])
def get_capture_tunnels(id: str, db: Session = Depends(get_db)):
    tunnels = db.query(Tunnel).filter(Tunnel.capture_id == id).all()
    result = []
    for t in tunnels:
        result.append(TunnelResponse(
            id=t.id,
            capture_id=t.capture_id,
            tunnel_key=t.tunnel_key,
            endpoint_a=t.endpoint_a,
            endpoint_b=t.endpoint_b,
            ike_version=t.ike_version,
            natt_enabled=t.natt_enabled,
            first_seen=t.first_seen,
            last_seen=t.last_seen,
            duration=t.duration,
            packet_count=t.packet_count,
            byte_count=t.byte_count,
            risk_score=t.risk_score,
            risk_level=t.risk_level,
            status=t.status,
            ike_sessions_count=len(t.ike_sessions),
            esp_sas_count=len(t.esp_sas),
            findings_count=len(t.findings)
        ))
    return result

@router.get("/{id}/findings", response_model=list[FindingResponse])
def get_capture_findings(id: str, db: Session = Depends(get_db)):
    findings = db.query(Finding).filter(Finding.capture_id == id).order_by(Finding.severity.desc()).all()
    return findings

@router.get("/{id}/risk", response_model=RiskAssessmentResponse)
def get_capture_risk(id: str, db: Session = Depends(get_db)):
    risk = db.query(RiskAssessment).filter(RiskAssessment.capture_id == id).first()
    if not risk:
        return RiskAssessmentResponse(
            overall_score=0.0,
            risk_level="INFORMATIONAL",
            crypto_score=0.0,
            key_mgmt_score=0.0,
            protocol_score=0.0,
            anomaly_score=0.0,
            metadata_score=0.0,
            weights={},
            contributors=[]
        )
    return RiskAssessmentResponse(
        overall_score=risk.overall_score,
        risk_level=risk.risk_level,
        crypto_score=risk.crypto_score,
        key_mgmt_score=risk.key_mgmt_score,
        protocol_score=risk.protocol_score,
        anomaly_score=risk.anomaly_score,
        metadata_score=risk.metadata_score,
        weights=risk.weights_json or {},
        contributors=risk.contributors_json or []
    )
