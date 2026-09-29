export type EvidenceType = 'OBSERVED' | 'DERIVED' | 'INFERRED' | 'UNOBSERVABLE';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export interface CaptureSummary {
  id: string;
  filename: string;
  file_size: number;
  sha256: string;
  packet_count: number;
  ike_packet_count: number;
  esp_packet_count: number;
  natt_packet_count: number;
  other_packet_count: number;
  status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'COMPLETED_WITH_LIMITATIONS';
  stage_progress: number;
  current_stage: string;
  created_at: string;
  completed_at?: string;
  error_message?: string;
  tunnels_count: number;
  findings_count: number;
  overall_risk_score: number;
  overall_risk_level: Severity;
}

export interface PacketMetadata {
  id: string;
  frame_number: number;
  timestamp: number;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  length: number;
  summary?: string;
  is_ike: boolean;
  is_esp: boolean;
  is_natt: boolean;
  spi?: string;
  raw_hex_preview?: string;
  detailed_json?: any;
}

export interface IKEProposal {
  id: string;
  proposal_number: number;
  protocol_id: string;
  spi?: string;
  encryption_alg?: string;
  key_length?: number;
  prf_alg?: string;
  integrity_alg?: string;
  dh_group?: string;
  assessment: string;
  frame_number?: number;
}

export interface IKESession {
  id: string;
  initiator_spi?: string;
  responder_spi?: string;
  ike_version: string;
  exchange_type?: string;
  message_id?: number;
  flags?: string;
  is_aggressive_mode: boolean;
  first_seen: number;
  last_seen: number;
  packet_count: number;
  proposals: IKEProposal[];
}

export interface ESPSA {
  id: string;
  spi: string;
  direction: string;
  source_ip: string;
  destination_ip: string;
  packet_count: number;
  byte_count: number;
  first_seen: number;
  last_seen: number;
  min_seq: number;
  max_seq: number;
  sequence_gaps: number;
  replay_suspect_count: number;
  mean_packet_size: number;
  std_packet_size: number;
  mean_iat: number;
  std_iat: number;
  burst_count: number;
  direction_ratio: number;
  is_natt: boolean;
}

export interface FlowWindow {
  id: string;
  window_index: number;
  start_time: number;
  end_time: number;
  packet_count: number;
  byte_count: number;
  mean_size: number;
  std_size: number;
  min_size: number;
  max_size: number;
  mean_iat: number;
  std_iat: number;
  upstream_ratio: number;
  burst_count: number;
  gap_count: number;
  predicted_class: string;
  class_confidence: number;
  shap_features?: Record<string, number>;
}

export interface EvidenceItem {
  id: string;
  frame_number: number;
  protocol: string;
  field_path: string;
  extracted_value: string;
  raw_bytes_hex?: string;
  notes?: string;
}

export interface Finding {
  id: string;
  capture_id: string;
  tunnel_id?: string;
  rule_id: string;
  title: string;
  severity: Severity;
  category: string;
  evidence_type: EvidenceType;
  description: string;
  technical_evidence: string;
  frame_references: number[];
  standards_reference: string;
  recommendation: string;
  confidence: number;
  status: string;
  evidence_items?: EvidenceItem[];
}

export interface Tunnel {
  id: string;
  capture_id: string;
  tunnel_key: string;
  endpoint_a: string;
  endpoint_b: string;
  ike_version?: string;
  natt_enabled: boolean;
  first_seen: number;
  last_seen: number;
  duration: number;
  packet_count: number;
  byte_count: number;
  risk_score: number;
  risk_level: Severity;
  status: string;
  ike_sessions_count: number;
  esp_sas_count: number;
  findings_count: number;
}

export interface TimelineEvent {
  timestamp: number;
  time_display: string;
  relative_seconds: number;
  event_type: string;
  summary: string;
  frame_number?: number;
  evidence_type: EvidenceType;
  details: Record<string, any>;
}

export interface DigitalTwin {
  tunnel_id: string;
  endpoint_a: string;
  endpoint_b: string;
  observed: Record<string, any>;
  derived: Record<string, any>;
  inferred: Record<string, any>;
  unobservable: Record<string, string>;
}

export interface RiskAssessment {
  overall_score: number;
  risk_level: Severity;
  crypto_score: number;
  key_mgmt_score: number;
  protocol_score: number;
  anomaly_score: number;
  metadata_score: number;
  weights: Record<string, number>;
  contributors: Array<{
    finding_id?: string;
    rule_id: string;
    title: string;
    category: string;
    severity: string;
    points: number;
    confidence: number;
    evidence_type: string;
  }>;
}

export interface ComparisonDiffItem {
  control: string;
  category: string;
  baseline_value: string;
  remediation_value: string;
  change_status: 'IMPROVED' | 'DEGRADED' | 'UNCHANGED' | 'NOT_APPLICABLE';
  rationale: string;
  standards_rule?: string;
}

export interface ComparisonResponse {
  baseline_capture_id: string;
  baseline_filename: string;
  remediation_capture_id: string;
  remediation_filename: string;
  baseline_risk_score: number;
  remediation_risk_score: number;
  risk_delta: number;
  diff_table: ComparisonDiffItem[];
  remediation_verified: boolean;
  summary: string;
}

export interface SystemStatus {
  project_name: string;
  project_subtitle: string;
  version: string;
  rulepack_version: string;
  ml_model_version: string;
  deployment_mode: string;
  external_apis: string;
  cloud_analysis: string;
  telemetry: string;
  analysis_engine: string;
  rule_engine: string;
  ml_model_status: string;
  database_status: string;
  tshark_available: boolean;
  active_captures_count: number;
  active_tunnels_count: number;
  active_rules_count: number;
}
