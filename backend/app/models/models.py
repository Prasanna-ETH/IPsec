import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON
)
from sqlalchemy.orm import relationship
from app.db.database import Base

def gen_uuid() -> str:
    return str(uuid.uuid4())

class Capture(Base):
    __tablename__ = "captures"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    filename = Column(String(255), nullable=False)
    filepath = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=False, default=0)
    sha256 = Column(String(64), nullable=False, index=True)
    packet_count = Column(Integer, default=0)
    ike_packet_count = Column(Integer, default=0)
    esp_packet_count = Column(Integer, default=0)
    natt_packet_count = Column(Integer, default=0)
    other_packet_count = Column(Integer, default=0)
    status = Column(String(32), default="PENDING")  # PENDING, PROCESSING, COMPLETED, FAILED, COMPLETED_WITH_LIMITATIONS
    stage_progress = Column(Integer, default=0)
    current_stage = Column(String(128), default="Initializing")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    tunnels = relationship("Tunnel", back_populates="capture", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="capture", cascade="all, delete-orphan")
    packets = relationship("PacketMetadata", back_populates="capture", cascade="all, delete-orphan")
    risk_assessment = relationship("RiskAssessment", back_populates="capture", uselist=False, cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="capture", cascade="all, delete-orphan")


class PacketMetadata(Base):
    __tablename__ = "packet_metadata"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    capture_id = Column(String(36), ForeignKey("captures.id"), nullable=False, index=True)
    frame_number = Column(Integer, nullable=False, index=True)
    timestamp = Column(Float, nullable=False)
    source_ip = Column(String(64), nullable=False)
    destination_ip = Column(String(64), nullable=False)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(32), nullable=False)  # IKEv1, IKEv2, ESP, NAT-T, UDP, TCP, OTHER
    length = Column(Integer, nullable=False)
    summary = Column(Text, nullable=True)
    
    is_ike = Column(Boolean, default=False)
    is_esp = Column(Boolean, default=False)
    is_natt = Column(Boolean, default=False)
    spi = Column(String(64), nullable=True, index=True)
    raw_hex_preview = Column(Text, nullable=True)
    detailed_json = Column(JSON, nullable=True)

    capture = relationship("Capture", back_populates="packets")


class Tunnel(Base):
    __tablename__ = "tunnels"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    capture_id = Column(String(36), ForeignKey("captures.id"), nullable=False, index=True)
    tunnel_key = Column(String(128), nullable=False, index=True)  # e.g., 192.168.1.1<->192.168.2.1
    endpoint_a = Column(String(64), nullable=False)
    endpoint_b = Column(String(64), nullable=False)
    ike_version = Column(String(16), nullable=True)  # IKEv1, IKEv2, NONE
    natt_enabled = Column(Boolean, default=False)
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False)
    duration = Column(Float, default=0.0)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(16), default="INFORMATIONAL")  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    status = Column(String(32), default="ACTIVE")

    capture = relationship("Capture", back_populates="tunnels")
    ike_sessions = relationship("IKESession", back_populates="tunnel", cascade="all, delete-orphan")
    esp_sas = relationship("ESPSecurityAssociation", back_populates="tunnel", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="tunnel", cascade="all, delete-orphan")
    flow_windows = relationship("FlowWindow", back_populates="tunnel", cascade="all, delete-orphan")


class IKESession(Base):
    __tablename__ = "ike_sessions"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    tunnel_id = Column(String(36), ForeignKey("tunnels.id"), nullable=False, index=True)
    capture_id = Column(String(36), ForeignKey("captures.id"), nullable=False)
    initiator_spi = Column(String(64), nullable=True, index=True)
    responder_spi = Column(String(64), nullable=True, index=True)
    ike_version = Column(String(16), nullable=False)  # IKEv1, IKEv2
    exchange_type = Column(String(64), nullable=True)  # IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL, Identity_Protection, Aggressive, etc.
    message_id = Column(Integer, nullable=True)
    flags = Column(String(64), nullable=True)
    is_aggressive_mode = Column(Boolean, default=False)
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False)
    packet_count = Column(Integer, default=0)

    tunnel = relationship("Tunnel", back_populates="ike_sessions")
    proposals = relationship("IKEProposal", back_populates="ike_session", cascade="all, delete-orphan")


class IKEProposal(Base):
    __tablename__ = "ike_proposals"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    ike_session_id = Column(String(36), ForeignKey("ike_sessions.id"), nullable=False, index=True)
    proposal_number = Column(Integer, default=1)
    protocol_id = Column(String(32), default="IKE")  # IKE, AH, ESP
    spi = Column(String(64), nullable=True)
    encryption_alg = Column(String(64), nullable=True)  # AES-GCM, AES-CBC, 3DES, DES, NULL
    key_length = Column(Integer, nullable=True)  # 256, 192, 128, 56
    prf_alg = Column(String(64), nullable=True)  # PRF_HMAC_SHA2_256, PRF_HMAC_MD5, etc.
    integrity_alg = Column(String(64), nullable=True)  # AUTH_HMAC_SHA2_256_128, AUTH_HMAC_MD5_96
    dh_group = Column(String(64), nullable=True)  # Group 14 (MODP-2048), Group 19 (ECP-256), Group 2 (MODP-1024)
    assessment = Column(String(32), default="SECURE")  # SECURE, WEAK, INSECURE, DEPRECATED
    frame_number = Column(Integer, nullable=True)

    ike_session = relationship("IKESession", back_populates="proposals")


class ESPSecurityAssociation(Base):
    __tablename__ = "esp_security_associations"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    tunnel_id = Column(String(36), ForeignKey("tunnels.id"), nullable=False, index=True)
    capture_id = Column(String(36), ForeignKey("captures.id"), nullable=False)
    spi = Column(String(64), nullable=False, index=True)  # e.g., 0xabcdef12
    direction = Column(String(32), default="BIDIRECTIONAL")  # INBOUND, OUTBOUND, INITIATOR_TO_RESPONDER
    source_ip = Column(String(64), nullable=False)
    destination_ip = Column(String(64), nullable=False)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False)
    min_seq = Column(Integer, default=0)
    max_seq = Column(Integer, default=0)
    sequence_gaps = Column(Integer, default=0)
    replay_suspect_count = Column(Integer, default=0)
    mean_packet_size = Column(Float, default=0.0)
    std_packet_size = Column(Float, default=0.0)
    mean_iat = Column(Float, default=0.0)
    std_iat = Column(Float, default=0.0)
    burst_count = Column(Integer, default=0)
    direction_ratio = Column(Float, default=1.0)
    is_natt = Column(Boolean, default=False)

    tunnel = relationship("Tunnel", back_populates="esp_sas")
    flow_windows = relationship("FlowWindow", back_populates="esp_sa", cascade="all, delete-orphan")


class FlowWindow(Base):
    __tablename__ = "flow_windows"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    tunnel_id = Column(String(36), ForeignKey("tunnels.id"), nullable=False, index=True)
    esp_sa_id = Column(String(36), ForeignKey("esp_security_associations.id"), nullable=True)
    window_index = Column(Integer, default=0)
    start_time = Column(Float, nullable=False)
    end_time = Column(Float, nullable=False)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    mean_size = Column(Float, default=0.0)
    std_size = Column(Float, default=0.0)
    min_size = Column(Integer, default=0)
    max_size = Column(Integer, default=0)
    mean_iat = Column(Float, default=0.0)
    std_iat = Column(Float, default=0.0)
    upstream_ratio = Column(Float, default=0.5)
    downstream_ratio = Column(Float, default=0.5)
    burst_count = Column(Integer, default=0)
    gap_count = Column(Integer, default=0)
    predicted_class = Column(String(64), default="UNKNOWN")  # INTERACTIVE, BULK_TRANSFER, VOIP_LIKE, VIDEO_LIKE, UNKNOWN
    class_confidence = Column(Float, default=0.0)
    shap_features = Column(JSON, nullable=True)

    tunnel = relationship("Tunnel", back_populates="flow_windows")
    esp_sa = relationship("ESPSecurityAssociation", back_populates="flow_windows")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    capture_id = Column(String(36), ForeignKey("captures.id"), nullable=False, index=True)
    tunnel_id = Column(String(36), ForeignKey("tunnels.id"), nullable=True, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(16), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    category = Column(String(64), nullable=False)  # CRYPTO, KEY_MGMT, PROTOCOL, ANOMALY, METADATA
    evidence_type = Column(String(32), nullable=False)  # OBSERVED, DERIVED, INFERRED, UNOBSERVABLE
    description = Column(Text, nullable=False)
    technical_evidence = Column(Text, nullable=False)
    frame_references = Column(JSON, default=list)  # list of frame numbers
    standards_reference = Column(String(255), nullable=False)  # e.g., RFC 8247 Sec 3, NIST SP 800-77
    recommendation = Column(Text, nullable=False)
    confidence = Column(Float, default=1.0)
    status = Column(String(32), default="OPEN")

    capture = relationship("Capture", back_populates="findings")
    tunnel = relationship("Tunnel", back_populates="findings")
    evidence_items = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False, index=True)
    capture_id = Column(String(36), ForeignKey("captures.id"), nullable=False)
    frame_number = Column(Integer, nullable=False)
    protocol = Column(String(32), nullable=False)
    field_path = Column(String(128), nullable=False)
    extracted_value = Column(String(255), nullable=False)
    raw_bytes_hex = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)

    finding = relationship("Finding", back_populates="evidence_items")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    capture_id = Column(String(36), ForeignKey("captures.id"), nullable=False, unique=True)
    tunnel_id = Column(String(36), ForeignKey("tunnels.id"), nullable=True)
    overall_score = Column(Float, nullable=False, default=0.0)  # 0 to 100
    risk_level = Column(String(16), default="LOW")  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    crypto_score = Column(Float, default=0.0)
    key_mgmt_score = Column(Float, default=0.0)
    protocol_score = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    metadata_score = Column(Float, default=0.0)
    weights_json = Column(JSON, nullable=True)
    contributors_json = Column(JSON, nullable=True)

    capture = relationship("Capture", back_populates="risk_assessment")


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    capture_id = Column(String(36), ForeignKey("captures.id"), nullable=False, index=True)
    report_type = Column(String(16), nullable=False)  # PDF, JSON
    filename = Column(String(255), nullable=False)
    filepath = Column(String(512), nullable=False)
    sha256 = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    capture = relationship("Capture", back_populates="reports")


class RulePackVersion(Base):
    __tablename__ = "rule_pack_versions"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    version_name = Column(String(64), nullable=False, unique=True)
    rules_count = Column(Integer, default=0)
    loaded_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
