from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.models import Tunnel, IKESession, IKEProposal, ESPSecurityAssociation, FlowWindow, Finding, PacketMetadata
from app.schemas.schemas import (
    TunnelResponse, IKESessionResponse, IKEProposalResponse, ESPSAResponse,
    FlowWindowResponse, FindingResponse, DigitalTwinResponse
)
from app.engines.sa_correlator import correlate_and_build_timeline
from app.engines.digital_twin_engine import build_digital_twin
from app.engines.risk_engine import RiskEngine

router = APIRouter(prefix="/tunnels", tags=["Tunnels"])

@router.get("/{id}", response_model=TunnelResponse)
def get_tunnel(id: str, db: Session = Depends(get_db)):
    t = db.query(Tunnel).filter(Tunnel.id == id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    return TunnelResponse(
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
    )

@router.get("/{id}/ike", response_model=list[IKESessionResponse])
def get_tunnel_ike(id: str, db: Session = Depends(get_db)):
    t = db.query(Tunnel).filter(Tunnel.id == id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    
    sessions = db.query(IKESession).filter(IKESession.tunnel_id == id).all()
    result = []
    for s in sessions:
        props = [
            IKEProposalResponse(
                id=p.id,
                proposal_number=p.proposal_number,
                protocol_id=p.protocol_id,
                spi=p.spi,
                encryption_alg=p.encryption_alg,
                key_length=p.key_length,
                prf_alg=p.prf_alg,
                integrity_alg=p.integrity_alg,
                dh_group=p.dh_group,
                assessment=p.assessment,
                frame_number=p.frame_number
            ) for p in s.proposals
        ]
        result.append(IKESessionResponse(
            id=s.id,
            initiator_spi=s.initiator_spi,
            responder_spi=s.responder_spi,
            ike_version=s.ike_version,
            exchange_type=s.exchange_type,
            message_id=s.message_id,
            flags=s.flags,
            is_aggressive_mode=s.is_aggressive_mode,
            first_seen=s.first_seen,
            last_seen=s.last_seen,
            packet_count=s.packet_count,
            proposals=props
        ))
    return result

@router.get("/{id}/esp", response_model=list[ESPSAResponse])
def get_tunnel_esp(id: str, db: Session = Depends(get_db)):
    t = db.query(Tunnel).filter(Tunnel.id == id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    
    sas = db.query(ESPSecurityAssociation).filter(ESPSecurityAssociation.tunnel_id == id).all()
    result = [
        ESPSAResponse(
            id=sa.id,
            spi=sa.spi,
            direction=sa.direction,
            source_ip=sa.source_ip,
            destination_ip=sa.destination_ip,
            packet_count=sa.packet_count,
            byte_count=sa.byte_count,
            first_seen=sa.first_seen,
            last_seen=sa.last_seen,
            min_seq=sa.min_seq,
            max_seq=sa.max_seq,
            sequence_gaps=sa.sequence_gaps,
            replay_suspect_count=sa.replay_suspect_count,
            mean_packet_size=sa.mean_packet_size,
            std_packet_size=sa.std_packet_size,
            mean_iat=sa.mean_iat,
            std_iat=sa.std_iat,
            burst_count=sa.burst_count,
            direction_ratio=sa.direction_ratio,
            is_natt=sa.is_natt
        ) for sa in sas
    ]
    return result

@router.get("/{id}/windows", response_model=list[FlowWindowResponse])
def get_tunnel_windows(id: str, db: Session = Depends(get_db)):
    windows = db.query(FlowWindow).filter(FlowWindow.tunnel_id == id).order_by(FlowWindow.window_index.asc()).all()
    return [
        FlowWindowResponse(
            id=w.id,
            window_index=w.window_index,
            start_time=w.start_time,
            end_time=w.end_time,
            packet_count=w.packet_count,
            byte_count=w.byte_count,
            mean_size=w.mean_size,
            std_size=w.std_size,
            min_size=w.min_size,
            max_size=w.max_size,
            mean_iat=w.mean_iat,
            std_iat=w.std_iat,
            upstream_ratio=w.upstream_ratio,
            burst_count=w.burst_count,
            gap_count=w.gap_count,
            predicted_class=w.predicted_class,
            class_confidence=w.class_confidence,
            shap_features=w.shap_features
        ) for w in windows
    ]

@router.get("/{id}/timeline")
def get_tunnel_timeline(id: str, db: Session = Depends(get_db)):
    t = db.query(Tunnel).filter(Tunnel.id == id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tunnel not found")

    # Fetch raw packets & objects
    packets = db.query(PacketMetadata).filter(
        PacketMetadata.capture_id == t.capture_id,
        (PacketMetadata.source_ip.in_([t.endpoint_a, t.endpoint_b])) &
        (PacketMetadata.destination_ip.in_([t.endpoint_a, t.endpoint_b]))
    ).all()

    ike_sessions = db.query(IKESession).filter(IKESession.tunnel_id == id).all()
    esp_sas = db.query(ESPSecurityAssociation).filter(ESPSecurityAssociation.tunnel_id == id).all()

    # Reconstruct dict context
    tunnel_dict = {
        "id": t.id,
        "endpoint_a": t.endpoint_a,
        "endpoint_b": t.endpoint_b,
        "ike_version": t.ike_version,
        "packets": [
            {
                "frame_number": p.frame_number,
                "timestamp": p.timestamp,
                "is_ike": p.is_ike,
                "is_esp": p.is_esp,
                "spi": p.spi,
                "detailed_json": p.detailed_json
            } for p in packets
        ],
        "ike_sessions": {
            f"{s.initiator_spi}_{s.responder_spi}": {
                "initiator_spi": s.initiator_spi,
                "responder_spi": s.responder_spi,
                "ike_version": s.ike_version,
                "exchange_type": s.exchange_type,
                "message_id": s.message_id,
                "is_aggressive_mode": s.is_aggressive_mode,
                "proposals": [
                    {
                        "proposal_number": prop.proposal_number,
                        "encryption_alg": prop.encryption_alg,
                        "dh_group": prop.dh_group
                    } for prop in s.proposals
                ]
            } for s in ike_sessions
        },
        "esp_sas": {
            sa.spi: {
                "spi": sa.spi,
                "direction": sa.direction,
                "source_ip": sa.source_ip,
                "destination_ip": sa.destination_ip,
                "first_seen": sa.first_seen,
            } for sa in esp_sas
        }
    }

    return correlate_and_build_timeline(tunnel_dict)

@router.get("/{id}/digital_twin", response_model=DigitalTwinResponse)
def get_tunnel_digital_twin(id: str, db: Session = Depends(get_db)):
    t = db.query(Tunnel).filter(Tunnel.id == id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tunnel not found")

    ike_sessions = db.query(IKESession).filter(IKESession.tunnel_id == id).all()
    esp_sas = db.query(ESPSecurityAssociation).filter(ESPSecurityAssociation.tunnel_id == id).all()

    tunnel_dict = {
        "id": t.id,
        "endpoint_a": t.endpoint_a,
        "endpoint_b": t.endpoint_b,
        "ike_version": t.ike_version,
        "natt_enabled": t.natt_enabled,
        "duration": t.duration,
        "packet_count": t.packet_count,
        "byte_count": t.byte_count,
        "ike_sessions": {
            s.id: {
                "initiator_spi": s.initiator_spi,
                "responder_spi": s.responder_spi,
                "proposals": [
                    {
                        "encryption_alg": p.encryption_alg,
                        "prf_alg": p.prf_alg,
                        "integrity_alg": p.integrity_alg,
                        "dh_group": p.dh_group
                    } for p in s.proposals
                ]
            } for s in ike_sessions
        },
        "esp_sas": {
            sa.spi: {
                "packet_count": sa.packet_count,
                "sequence_gaps": sa.sequence_gaps,
                "replay_suspect_count": sa.replay_suspect_count,
                "burst_count": sa.burst_count
            } for sa in esp_sas
        }
    }

    twin = build_digital_twin(tunnel_dict)
    return DigitalTwinResponse(
        tunnel_id=twin["tunnel_id"],
        endpoint_a=twin["endpoint_a"],
        endpoint_b=twin["endpoint_b"],
        observed=twin["observed"],
        derived=twin["derived"],
        inferred=twin["inferred"],
        unobservable=twin["unobservable"]
    )
