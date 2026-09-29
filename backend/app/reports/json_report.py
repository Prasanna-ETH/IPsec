"""
Structured JSON Security Assessment Report Generator for OMEGA Platform.
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any
from app.core.config import settings

def generate_json_report(
    capture_data: dict[str, Any],
    tunnels_data: list[dict[str, Any]],
    findings_data: list[dict[str, Any]],
    risk_data: dict[str, Any],
    output_path: Path
) -> str:
    """
    Generates a structured JSON assessment artifact and returns its SHA-256.
    """
    report_dict = {
        "metadata": {
            "platform": settings.PROJECT_NAME,
            "platform_subtitle": settings.PROJECT_SUBTITLE,
            "engine_version": settings.VERSION,
            "rulepack_version": settings.RULEPACK_VERSION,
            "generation_time_utc": datetime.utcnow().isoformat(),
            "target_capture_filename": capture_data.get("filename"),
            "target_capture_sha256": capture_data.get("sha256"),
            "operating_mode": "AIR-GAPPED / SOVEREIGN LOCAL",
        },
        "capture_summary": {
            "packet_count": capture_data.get("packet_count", 0),
            "ike_packets": capture_data.get("ike_packet_count", 0),
            "esp_packets": capture_data.get("esp_packet_count", 0),
            "natt_packets": capture_data.get("natt_packet_count", 0),
            "other_packets": capture_data.get("other_packet_count", 0),
            "status": capture_data.get("status"),
        },
        "risk_breakdown": risk_data,
        "tunnels": tunnels_data,
        "security_findings": findings_data,
        "visibility_boundary": {
            "principle": "OBSERVED != DERIVED != INFERRED != UNOBSERVABLE",
            "unobservable_elements": [
                "ESP plaintext payload data",
                "Inner IP address encapsulation in Tunnel Mode",
                "Inner TCP/UDP transport port numbers",
                "Cryptographic Pre-Shared Keys (PSK)",
                "Private Diffie-Hellman / RSA keys",
                "IKEv2 IKE_AUTH encrypted peer identities"
            ]
        }
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, default=str)

    with open(output_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    return sha256
