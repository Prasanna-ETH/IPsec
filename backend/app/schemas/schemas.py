from typing import Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field
from app.core.visibility import EvidenceType

class CaptureBase(BaseModel):
    filename: str
    file_size: int
    sha256: str

class CaptureCreateResponse(BaseModel):
    id: str
    filename: str
    file_size: int
    sha256: str
    status: str
    stage_progress: int
    current_stage: str
    created_at: datetime

class CaptureSummaryResponse(BaseModel):
    id: str
    filename: str
    file_size: int
    sha256: str
    packet_count: int
    ike_packet_count: int
    esp_packet_count: int
    natt_packet_count: int
    other_packet_count: int
    status: str
    stage_progress: int
    current_stage: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    tunnels_count: int = 0
    findings_count: int = 0
    overall_risk_score: float = 0.0
    overall_risk_level: str = "INFORMATIONAL"

class PacketMetadataResponse(BaseModel):
    id: str
    frame_number: int
    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str
    length: int
    summary: Optional[str] = None
    is_ike: bool
    is_esp: bool
    is_natt: bool
    spi: Optional[str] = None
    raw_hex_preview: Optional[str] = None
    detailed_json: Optional[dict[str, Any]] = None

class PacketListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    packets: list[PacketMetadataResponse]

class IKEProposalResponse(BaseModel):
    id: str
    proposal_number: int
    protocol_id: str
    spi: Optional[str] = None
    encryption_alg: Optional[str] = None
    key_length: Optional[int] = None
    prf_alg: Optional[str] = None
    integrity_alg: Optional[str] = None
    dh_group: Optional[str] = None
    assessment: str
    frame_number: Optional[int] = None

class IKESessionResponse(BaseModel):
    id: str
    initiator_spi: Optional[str] = None
    responder_spi: Optional[str] = None
    ike_version: str
    exchange_type: Optional[str] = None
    message_id: Optional[int] = None
    flags: Optional[str] = None
    is_aggressive_mode: bool
    first_seen: float
    last_seen: float
    packet_count: int
    proposals: list[IKEProposalResponse] = []

class ESPSAResponse(BaseModel):
    id: str
    spi: str
    direction: str
    source_ip: str
    destination_ip: str
    packet_count: int
    byte_count: int
    first_seen: float
    last_seen: float
    min_seq: int
    max_seq: int
    sequence_gaps: int
    replay_suspect_count: int
    mean_packet_size: float
    std_packet_size: float
    mean_iat: float
    std_iat: float
    burst_count: int
    direction_ratio: float
    is_natt: bool

class FlowWindowResponse(BaseModel):
    id: str
    window_index: int
    start_time: float
    end_time: float
    packet_count: int
    byte_count: int
    mean_size: float
    std_size: float
    min_size: int
    max_size: int
    mean_iat: float
    std_iat: float
    upstream_ratio: float
    burst_count: int
    gap_count: int
    predicted_class: str
    class_confidence: float
    shap_features: Optional[dict[str, float]] = None

class EvidenceItemResponse(BaseModel):
    id: str
    frame_number: int
    protocol: str
    field_path: str
    extracted_value: str
    raw_bytes_hex: Optional[str] = None
    notes: Optional[str] = None

class FindingResponse(BaseModel):
    id: str
    capture_id: str
    tunnel_id: Optional[str] = None
    rule_id: str
    title: str
    severity: str
    category: str
    evidence_type: EvidenceType
    description: str
    technical_evidence: str
    frame_references: list[int] = []
    standards_reference: str
    recommendation: str
    confidence: float
    status: str
    evidence_items: list[EvidenceItemResponse] = []

class TunnelResponse(BaseModel):
    id: str
    capture_id: str
    tunnel_key: str
    endpoint_a: str
    endpoint_b: str
    ike_version: Optional[str] = None
    natt_enabled: bool
    first_seen: float
    last_seen: float
    duration: float
    packet_count: int
    byte_count: int
    risk_score: float
    risk_level: str
    status: str
    ike_sessions_count: int = 0
    esp_sas_count: int = 0
    findings_count: int = 0

class TimelineEvent(BaseModel):
    timestamp: float
    time_display: str
    event_type: str
    summary: str
    frame_number: Optional[int] = None
    evidence_type: EvidenceType
    details: dict[str, Any] = {}

class DigitalTwinResponse(BaseModel):
    tunnel_id: str
    endpoint_a: str
    endpoint_b: str
    observed: dict[str, Any]
    derived: dict[str, Any]
    inferred: dict[str, Any]
    unobservable: dict[str, str]

class RiskAssessmentResponse(BaseModel):
    overall_score: float
    risk_level: str
    crypto_score: float
    key_mgmt_score: float
    protocol_score: float
    anomaly_score: float
    metadata_score: float
    weights: dict[str, float]
    contributors: list[dict[str, Any]]

class ComparisonDiffItem(BaseModel):
    control: str
    category: str
    baseline_value: str
    remediation_value: str
    change_status: str  # IMPROVED, DEGRADED, UNCHANGED, NOT_APPLICABLE
    rationale: str
    standards_rule: Optional[str] = None

class ComparisonResponse(BaseModel):
    baseline_capture_id: str
    baseline_filename: str
    remediation_capture_id: str
    remediation_filename: str
    baseline_risk_score: float
    remediation_risk_score: float
    risk_delta: float
    diff_table: list[ComparisonDiffItem]
    remediation_verified: bool
    summary: str

class SystemStatusResponse(BaseModel):
    project_name: str
    project_subtitle: str
    version: str
    rulepack_version: str
    ml_model_version: str
    deployment_mode: str  # AIR-GAPPED / LOCAL
    external_apis: str  # DISABLED
    cloud_analysis: str  # NONE
    telemetry: str  # DISABLED
    analysis_engine: str  # ONLINE (LOCAL)
    rule_engine: str  # ACTIVE
    ml_model_status: str
    database_status: str
    tshark_available: bool
    active_captures_count: int
    active_tunnels_count: int
    active_rules_count: int
