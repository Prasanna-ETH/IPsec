"""
Security Association (SA) Correlation & Lifecycle Timeline Engine.
Reconstructs chronological cryptographic transitions:
IKE_SA_INIT -> IKE_AUTH -> Child/ESP SA Setup -> Rekeying / CREATE_CHILD_SA.
"""

from typing import Any
from datetime import datetime
from app.core.visibility import EvidenceType

def correlate_and_build_timeline(tunnel: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Builds a structured forensic chronological timeline of SA lifecycle events.
    """
    events: list[dict[str, Any]] = []
    packets = tunnel.get("packets", [])
    ike_sessions = tunnel.get("ike_sessions", {})
    esp_sas = tunnel.get("esp_sas", {})

    # Sort packets chronologically
    sorted_pkts = sorted(packets, key=lambda p: p.get("timestamp", 0.0))
    first_time = sorted_pkts[0]["timestamp"] if sorted_pkts else 0.0

    # 1. Timeline of IKE handshakes
    seen_ike_exchanges = set()
    for pkt in sorted_pkts:
        if pkt.get("is_ike") and pkt.get("detailed_json"):
            ike = pkt["detailed_json"]
            exch = ike.get("exchange_type", "IKE_EXCHANGE")
            f_num = pkt.get("frame_number")
            ts = pkt.get("timestamp", 0.0)
            rel_sec = round(ts - first_time, 2)
            time_str = datetime.utcfromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]

            key = f"{exch}_{ike.get('initiator_spi')}_{ike.get('message_id')}_{ike.get('is_response')}"
            if key not in seen_ike_exchanges:
                seen_ike_exchanges.add(key)
                role = "Response" if ike.get("is_response") else "Request"
                events.append({
                    "timestamp": ts,
                    "time_display": time_str,
                    "relative_seconds": rel_sec,
                    "event_type": "IKE_EXCHANGE",
                    "summary": f"{exch} {role} (Init SPI: {ike.get('initiator_spi')})",
                    "frame_number": f_num,
                    "evidence_type": EvidenceType.OBSERVED,
                    "details": {
                        "exchange": exch,
                        "message_id": ike.get("message_id"),
                        "proposals_count": len(ike.get("proposals", [])),
                        "has_ke": ike.get("has_ke", False),
                        "has_nonce": ike.get("has_nonce", False)
                    }
                })

                # If proposals are in this packet, add proposal extraction event
                if ike.get("proposals"):
                    p_summaries = [f"Prop {p.get('proposal_number')}: {p.get('encryption_alg')}/{p.get('dh_group')}" for p in ike["proposals"][:2]]
                    events.append({
                        "timestamp": ts + 0.0001,
                        "time_display": time_str,
                        "relative_seconds": rel_sec,
                        "event_type": "PROPOSAL_OBSERVED",
                        "summary": f"Cryptographic Proposals extracted: {', '.join(p_summaries)}",
                        "frame_number": f_num,
                        "evidence_type": EvidenceType.OBSERVED,
                        "details": {"proposals": ike["proposals"]}
                    })

    # 2. Timeline of ESP SA appearances and rekeys
    for spi, sa in esp_sas.items():
        ts_first = sa.get("first_seen", 0.0)
        time_first_str = datetime.utcfromtimestamp(ts_first).strftime("%H:%M:%S.%f")[:-3]
        first_frame = None
        for p in sorted_pkts:
            if p.get("spi") == spi:
                first_frame = p.get("frame_number")
                break

        events.append({
            "timestamp": ts_first,
            "time_display": time_first_str,
            "relative_seconds": round(ts_first - first_time, 2),
            "event_type": "ESP_SA_FIRST_OBSERVED",
            "summary": f"ESP Security Association {spi} first active ({sa.get('direction')})",
            "frame_number": first_frame,
            "evidence_type": EvidenceType.OBSERVED,
            "details": {
                "spi": spi,
                "direction": sa.get("direction"),
                "source_ip": sa.get("source_ip"),
                "destination_ip": sa.get("destination_ip"),
            }
        })

    # Sort all events chronologically
    events.sort(key=lambda e: e["timestamp"])
    return events
