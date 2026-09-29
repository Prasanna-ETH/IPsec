import os
import pytest
from pathlib import Path
from app.core.config import settings
from app.parsers.pcap_parser import iter_pcap_packets
from app.engines.session_builder import build_sessions_and_tunnels
from app.engines.rule_engine import RuleEngine
from app.engines.risk_engine import RiskEngine
from app.engines.digital_twin_engine import build_digital_twin
from app.engines.comparison_engine import compare_captures_data

SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent / "sample_captures"

def test_hardened_pcap_parsing():
    pcap_path = str(SAMPLE_DIR / "ikev2_hardened_aes_gcm.pcap")
    assert os.path.exists(pcap_path)

    pkts = list(iter_pcap_packets(pcap_path))
    assert len(pkts) > 0

    ike_pkts = [p for p in pkts if p["is_ike"]]
    esp_pkts = [p for p in pkts if p["is_esp"]]

    assert len(ike_pkts) >= 2
    assert len(esp_pkts) > 0

    # Build tunnels
    tunnels = build_sessions_and_tunnels(pkts)
    assert len(tunnels) == 1
    t = list(tunnels.values())[0]
    assert t["ike_version"] == "IKEv2"

    # Evaluate rules
    rule_engine = RuleEngine()
    findings = rule_engine.evaluate(t, "test-cap-1")

    # Risk calculation
    risk_engine = RiskEngine()
    risk = risk_engine.calculate_risk(findings)
    assert "overall_score" in risk

    # Digital twin
    twin = build_digital_twin(t)
    assert "observed" in twin
    assert "unobservable" in twin
    assert "esp_plaintext_payload" in twin["unobservable"]


def test_legacy_pcap_detection():
    pcap_path = str(SAMPLE_DIR / "ikev1_legacy_3des_sha1.pcap")
    assert os.path.exists(pcap_path)

    pkts = list(iter_pcap_packets(pcap_path))
    tunnels = build_sessions_and_tunnels(pkts)
    t = list(tunnels.values())[0]

    rule_engine = RuleEngine()
    findings = rule_engine.evaluate(t, "test-cap-2")
    rule_ids = [f["rule_id"] for f in findings]

    # Should detect IKEv1 deprecation
    assert "IPSEC-IKE-001" in rule_ids

    # Should calculate elevated risk
    risk_engine = RiskEngine()
    risk = risk_engine.calculate_risk(findings)
    assert risk["overall_score"] > 0


def test_comparison_engine():
    base = {
        "id": "1",
        "filename": "legacy.pcap",
        "ike_version": "IKEv1",
        "encryption_alg": "3DES-CBC",
        "dh_group": "Group 2 (MODP-1024)",
        "integrity_alg": "AUTH_HMAC_MD5_96",
        "risk_score": 82.0
    }
    remed = {
        "id": "2",
        "filename": "hardened.pcap",
        "ike_version": "IKEv2",
        "encryption_alg": "AES-256-GCM",
        "dh_group": "Group 19 (ECP-256)",
        "integrity_alg": "AUTH_HMAC_SHA2_256_128",
        "risk_score": 18.0
    }
    comp = compare_captures_data(base, remed)
    assert comp["remediation_verified"] is True
    assert comp["risk_delta"] < 0
    statuses = [item["change_status"] for item in comp["diff_table"]]
    assert "IMPROVED" in statuses
