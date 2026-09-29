"""
Full 12-Stage IPsec Capture Analysis Service for OMEGA Platform.
Coordinates packet parsing, protocol detection, session building,
rule evaluation, ML flow classification, risk calculation, and evidence indexing.
"""

import os
import hashlib
from datetime import datetime
from typing import Any
from sqlalchemy.orm import Session
from app.db.database import SessionLocal
from app.models.models import (
    Capture, PacketMetadata, Tunnel, IKESession, IKEProposal,
    ESPSecurityAssociation, FlowWindow, Finding, Evidence, RiskAssessment
)
from app.parsers.pcap_parser import iter_pcap_packets
from app.engines.session_builder import build_sessions_and_tunnels
from app.engines.rule_engine import RuleEngine
from app.engines.anomaly_engine import AnomalyEngine
from app.engines.risk_engine import RiskEngine
from app.engines.sa_correlator import correlate_and_build_timeline
from app.ml.feature_extractor import extract_flow_features
from app.ml.inference import classifier
from app.ml.explain import explain_prediction

class AnalysisService:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.anomaly_engine = AnomalyEngine()
        self.risk_engine = RiskEngine()

    def process_capture(self, capture_id: str):
        """
        Executes the 12-stage analysis pipeline synchronously or in background task.
        """
        db: Session = SessionLocal()
        try:
            capture = db.query(Capture).filter(Capture.id == capture_id).first()
            if not capture:
                return

            capture.status = "PROCESSING"
            capture.current_stage = "1. Validating capture"
            capture.stage_progress = 8
            db.commit()

            # Stage 1: Validate file
            if not os.path.exists(capture.filepath):
                capture.status = "FAILED"
                capture.error_message = "Capture file not found on disk."
                db.commit()
                return

            # Stage 2: Parsing packets
            capture.current_stage = "2. Parsing packets"
            capture.stage_progress = 16
            db.commit()

            packet_records = []
            ike_count = 0
            esp_count = 0
            natt_count = 0
            other_count = 0

            for pkt_meta in iter_pcap_packets(capture.filepath):
                packet_records.append(pkt_meta)
                if pkt_meta.get("is_ike"):
                    ike_count += 1
                elif pkt_meta.get("is_esp"):
                    esp_count += 1
                elif pkt_meta.get("is_natt"):
                    natt_count += 1
                else:
                    other_count += 1

                # Save packet metadata to DB (batch if large)
                p_db = PacketMetadata(
                    capture_id=capture.id,
                    frame_number=pkt_meta["frame_number"],
                    timestamp=pkt_meta["timestamp"],
                    source_ip=pkt_meta["source_ip"],
                    destination_ip=pkt_meta["destination_ip"],
                    source_port=pkt_meta["source_port"],
                    destination_port=pkt_meta["destination_port"],
                    protocol=pkt_meta["protocol"],
                    length=pkt_meta["length"],
                    summary=pkt_meta["summary"],
                    is_ike=pkt_meta["is_ike"],
                    is_esp=pkt_meta["is_esp"],
                    is_natt=pkt_meta["is_natt"],
                    spi=pkt_meta["spi"],
                    raw_hex_preview=pkt_meta["raw_hex_preview"],
                    detailed_json=pkt_meta.get("detailed_json")
                )
                db.add(p_db)

            capture.packet_count = len(packet_records)
            capture.ike_packet_count = ike_count
            capture.esp_packet_count = esp_count
            capture.natt_packet_count = natt_count
            capture.other_packet_count = other_count
            db.commit()

            # Stage 3, 4, 5: Building sessions & tunnels
            capture.current_stage = "5. Building sessions & tunnels"
            capture.stage_progress = 40
            db.commit()

            tunnels_dict = build_sessions_and_tunnels(packet_records)

            # Stage 6, 7, 8: Correlating Security Associations & Features
            capture.current_stage = "8. Correlating Security Associations"
            capture.stage_progress = 65
            db.commit()

            all_findings = []
            tunnel_db_models = []

            for t_key, t_data in tunnels_dict.items():
                t_model = Tunnel(
                    capture_id=capture.id,
                    tunnel_key=t_key,
                    endpoint_a=t_data["endpoint_a"],
                    endpoint_b=t_data["endpoint_b"],
                    ike_version=t_data["ike_version"],
                    natt_enabled=t_data["natt_enabled"],
                    first_seen=t_data["first_seen"],
                    last_seen=t_data["last_seen"],
                    duration=t_data["duration"],
                    packet_count=t_data["packet_count"],
                    byte_count=t_data["byte_count"],
                    risk_score=0.0,
                    risk_level="INFORMATIONAL",
                    status="ACTIVE"
                )
                db.add(t_model)
                db.flush()  # get t_model.id
                t_data["id"] = t_model.id
                tunnel_db_models.append(t_model)

                # Persist IKE sessions and proposals
                for s_key, s_data in t_data["ike_sessions"].items():
                    s_model = IKESession(
                        tunnel_id=t_model.id,
                        capture_id=capture.id,
                        initiator_spi=s_data["initiator_spi"],
                        responder_spi=s_data["responder_spi"],
                        ike_version=s_data["ike_version"],
                        exchange_type=s_data["exchange_type"],
                        message_id=s_data["message_id"],
                        is_aggressive_mode=s_data["is_aggressive_mode"],
                        first_seen=s_data["first_seen"],
                        last_seen=s_data["last_seen"],
                        packet_count=s_data["packet_count"]
                    )
                    db.add(s_model)
                    db.flush()

                    for prop in s_data.get("proposals", []):
                        p_model = IKEProposal(
                            ike_session_id=s_model.id,
                            proposal_number=prop.get("proposal_number", 1),
                            protocol_id=prop.get("protocol_id", "IKE"),
                            spi=prop.get("spi"),
                            encryption_alg=prop.get("encryption_alg"),
                            key_length=prop.get("key_length"),
                            prf_alg=prop.get("prf_alg"),
                            integrity_alg=prop.get("integrity_alg"),
                            dh_group=prop.get("dh_group"),
                            assessment=prop.get("assessment", "SECURE"),
                            frame_number=prop.get("frame_number")
                        )
                        db.add(p_model)

                # Persist ESP SAs and Flow Windows
                for spi_key, sa_data in t_data["esp_sas"].items():
                    sa_model = ESPSecurityAssociation(
                        tunnel_id=t_model.id,
                        capture_id=capture.id,
                        spi=spi_key,
                        direction=sa_data.get("direction", "BIDIRECTIONAL"),
                        source_ip=sa_data.get("source_ip", ""),
                        destination_ip=sa_data.get("destination_ip", ""),
                        packet_count=sa_data.get("packet_count", 0),
                        byte_count=sa_data.get("byte_count", 0),
                        first_seen=sa_data.get("first_seen", 0.0),
                        last_seen=sa_data.get("last_seen", 0.0),
                        min_seq=sa_data.get("min_seq", 0),
                        max_seq=sa_data.get("max_seq", 0),
                        sequence_gaps=sa_data.get("sequence_gaps", 0),
                        replay_suspect_count=sa_data.get("replay_suspect_count", 0),
                        mean_packet_size=sa_data.get("mean_packet_size", 0.0),
                        std_packet_size=sa_data.get("std_packet_size", 0.0),
                        mean_iat=sa_data.get("mean_iat", 0.0),
                        std_iat=sa_data.get("std_iat", 0.0),
                        burst_count=sa_data.get("burst_count", 0),
                        direction_ratio=sa_data.get("direction_ratio", 1.0),
                        is_natt=sa_data.get("is_natt", False)
                    )
                    db.add(sa_model)
                    db.flush()

                    # Extract flow windows for ML behavioral analysis
                    esp_pkts = [p for p in t_data["packets"] if p.get("spi") == spi_key]
                    flow_wins = extract_flow_features(esp_pkts)
                    for fw in flow_wins:
                        pred_class, conf = classifier.predict_window(fw)
                        shaps = explain_prediction(fw, pred_class)
                        fw_model = FlowWindow(
                            tunnel_id=t_model.id,
                            esp_sa_id=sa_model.id,
                            window_index=fw.get("window_index", 0),
                            start_time=fw.get("start_time", 0.0),
                            end_time=fw.get("end_time", 0.0),
                            packet_count=fw.get("packet_count", 0),
                            byte_count=fw.get("byte_count", 0),
                            mean_size=fw.get("mean_packet_size", 0.0),
                            std_size=fw.get("std_packet_size", 0.0),
                            min_size=fw.get("min_packet_size", 0),
                            max_size=fw.get("max_packet_size", 0),
                            mean_iat=fw.get("mean_iat", 0.0),
                            std_iat=fw.get("std_iat", 0.0),
                            upstream_ratio=fw.get("upstream_ratio", 0.5),
                            burst_count=fw.get("burst_count", 0),
                            gap_count=fw.get("sequence_gap_count", 0),
                            predicted_class=pred_class,
                            class_confidence=conf,
                            shap_features=shaps
                        )
                        db.add(fw_model)

                # Stage 9: Run standards rules
                tunnel_findings = self.rule_engine.evaluate(t_data, capture.id)
                # Stage 10: Run statistical anomaly rules
                anomaly_findings = self.anomaly_engine.analyze_tunnel(t_data, capture.id)

                all_t_findings = tunnel_findings + anomaly_findings
                all_findings.extend(all_t_findings)

                # Calculate tunnel-specific risk
                t_risk = self.risk_engine.calculate_risk(all_t_findings)
                t_model.risk_score = t_risk["overall_score"]
                t_model.risk_level = t_risk["risk_level"]

            # Stage 11 & 12: Explainable Risk and Evidence Indexing
            capture.current_stage = "11. Calculating security posture & explainable risk"
            capture.stage_progress = 90
            db.commit()

            # Persist findings & evidence
            for f in all_findings:
                f_model = Finding(
                    capture_id=capture.id,
                    tunnel_id=f.get("tunnel_id"),
                    rule_id=f.get("rule_id", "IPSEC-GEN-001"),
                    title=f.get("title", ""),
                    severity=f.get("severity", "MEDIUM"),
                    category=f.get("category", "PROTOCOL"),
                    evidence_type=f.get("evidence_type", "OBSERVED"),
                    description=f.get("description", ""),
                    technical_evidence=f.get("technical_evidence", ""),
                    frame_references=f.get("frame_references", []),
                    standards_reference=f.get("standards_reference", ""),
                    recommendation=f.get("recommendation", ""),
                    confidence=f.get("confidence", 1.0),
                    status=f.get("status", "OPEN")
                )
                db.add(f_model)
                db.flush()

                for ev in f.get("evidence_items", []):
                    ev_model = Evidence(
                        finding_id=f_model.id,
                        capture_id=capture.id,
                        frame_number=ev.get("frame_number", 0),
                        protocol=ev.get("protocol", "IPsec"),
                        field_path=ev.get("field_path", "header"),
                        extracted_value=ev.get("extracted_value", ""),
                        raw_bytes_hex=ev.get("raw_bytes_hex"),
                        notes=ev.get("notes")
                    )
                    db.add(ev_model)

            # Overall capture risk assessment
            cap_risk = self.risk_engine.calculate_risk(all_findings)
            risk_model = RiskAssessment(
                capture_id=capture.id,
                overall_score=cap_risk["overall_score"],
                risk_level=cap_risk["risk_level"],
                crypto_score=cap_risk["crypto_score"],
                key_mgmt_score=cap_risk["key_mgmt_score"],
                protocol_score=cap_risk["protocol_score"],
                anomaly_score=cap_risk["anomaly_score"],
                metadata_score=cap_risk["metadata_score"],
                weights_json=cap_risk["weights"],
                contributors_json=cap_risk["contributors"]
            )
            db.add(risk_model)

            # Completion
            if len(packet_records) > 0 and ike_count == 0 and esp_count > 0:
                capture.status = "COMPLETED_WITH_LIMITATIONS"
                capture.error_message = "IKE handshake was not captured. ESP metadata analysis remains fully available."
            elif len(packet_records) == 0:
                capture.status = "COMPLETED_WITH_LIMITATIONS"
                capture.error_message = "Capture contains 0 packets."
            else:
                capture.status = "COMPLETED"

            capture.stage_progress = 100
            capture.current_stage = "12. Analysis complete"
            capture.completed_at = datetime.utcnow()
            db.commit()

        except Exception as exc:
            db.rollback()
            capture = db.query(Capture).filter(Capture.id == capture_id).first()
            if capture:
                capture.status = "FAILED"
                capture.error_message = f"Processing exception: {str(exc)}"
                db.commit()
            print(f"[AnalysisService] Error processing capture {capture_id}: {exc}")
        finally:
            db.close()

analysis_service = AnalysisService()
