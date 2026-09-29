"""
NAT-Traversal (UDP 4500) Protocol Classifier & Parser.
Distinguishes:
1. IKEv2 packet with Non-ESP Marker (4 bytes 0x00000000)
2. ESP packet in UDP encapsulation (SPI != 0 in first 4 bytes)
3. NAT Keepalive packet (1-byte 0xFF)
Follows RFC 3948.
"""

from typing import Any
import struct
from app.parsers.ike_parser import parse_ike_payload
from app.parsers.esp_parser import parse_esp_header

def parse_natt_payload(raw_bytes: bytes, frame_num: int, timestamp: float) -> dict[str, Any]:
    """
    Parses a UDP port 4500 payload safely.
    """
    if len(raw_bytes) == 1 and raw_bytes[0] == 0xFF:
        return {
            "is_natt": True,
            "natt_type": "NAT_KEEPALIVE",
            "protocol": "NAT-T",
            "summary": "NAT-Traversal Keepalive (0xFF)",
            "is_ike": False,
            "is_esp": False,
            "spi": None,
        }

    if len(raw_bytes) >= 4:
        first_four = struct.unpack("!I", raw_bytes[0:4])[0]
        if first_four == 0:
            # Non-ESP Marker present -> Following bytes are IKE payload
            ike_data = raw_bytes[4:]
            ike_res = parse_ike_payload(ike_data, frame_num)
            ike_res["is_natt"] = True
            ike_res["natt_type"] = "IKE_NON_ESP_MARKER"
            ike_res["protocol"] = ike_res.get("ike_version", "IKE")
            ike_res["summary"] = f"NAT-T IKE Encapsulation: {ike_res.get('exchange_type', 'IKE')}"
            return ike_res
        else:
            # Non-zero first four bytes -> Encapsulated ESP (first 4 bytes is ESP SPI)
            esp_res = parse_esp_header(raw_bytes, frame_num, timestamp)
            esp_res["is_natt"] = True
            esp_res["natt_type"] = "ESP_ENCAPSULATED"
            esp_res["protocol"] = "ESP"
            esp_res["summary"] = f"NAT-T ESP (SPI: {esp_res.get('spi')}, Seq: {esp_res.get('sequence_number')})"
            return esp_res

    return {
        "is_natt": True,
        "natt_type": "UNKNOWN",
        "protocol": "NAT-T",
        "summary": "Malformed or short UDP 4500 payload",
        "is_ike": False,
        "is_esp": False,
        "spi": None,
    }
