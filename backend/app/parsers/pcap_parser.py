"""
Resilient PCAP and PCAPNG Network Capture Parser.
Extracts unencrypted frame metadata, classifies protocols, and invokes
IKE, ESP, and NAT-T sub-parsers. Never crashes on malformed packets.
"""

import os
from typing import Generator, Any
from scapy.all import PcapReader, rdpcap, IP, IPv6, UDP, Raw
from scapy.layers.ipsec import ESP
from app.parsers.ike_parser import parse_ike_payload
from app.parsers.esp_parser import parse_esp_header
from app.parsers.natt_parser import parse_natt_payload

def iter_pcap_packets(filepath: str) -> Generator[dict[str, Any], None, None]:
    """
    Iterates through packets in a PCAP or PCAPNG file and yields structured metadata.
    """
    if not os.path.exists(filepath):
        return

    frame_num = 0
    try:
        with PcapReader(filepath) as pcap_reader:
            for pkt in pcap_reader:
                frame_num += 1
                try:
                    meta = _process_single_packet(pkt, frame_num)
                    if meta:
                        yield meta
                except Exception as exc:
                    # Never crash analysis pipeline on single packet decode error
                    yield {
                        "frame_number": frame_num,
                        "timestamp": float(getattr(pkt, "time", 0.0)),
                        "source_ip": "UNKNOWN",
                        "destination_ip": "UNKNOWN",
                        "source_port": None,
                        "destination_port": None,
                        "protocol": "MALFORMED",
                        "length": len(pkt) if hasattr(pkt, "__len__") else 0,
                        "summary": f"Parse warning: {str(exc)}",
                        "is_ike": False,
                        "is_esp": False,
                        "is_natt": False,
                        "spi": None,
                        "raw_hex_preview": bytes(pkt)[:64].hex() if hasattr(pkt, "__bytes__") else "",
                        "detailed_json": {"error": str(exc)}
                    }
    except Exception as top_exc:
        # If PcapReader fails on entire file (e.g. specialized pcapng block), fallback to rdpcap
        try:
            pkts = rdpcap(filepath)
            for idx, pkt in enumerate(pkts, start=1):
                try:
                    meta = _process_single_packet(pkt, idx)
                    if meta:
                        yield meta
                except Exception:
                    pass
        except Exception:
            pass


def _process_single_packet(pkt: Any, frame_num: int) -> dict[str, Any]:
    timestamp = float(getattr(pkt, "time", 0.0))
    pkt_len = len(pkt)
    raw_bytes = bytes(pkt)
    hex_preview = raw_bytes[:64].hex()

    src_ip = "UNKNOWN"
    dst_ip = "UNKNOWN"
    src_port = None
    dst_port = None
    proto_str = "OTHER"
    is_ike = False
    is_esp = False
    is_natt = False
    spi = None
    summary = pkt.summary() if hasattr(pkt, "summary") else "Raw packet"
    detailed: dict[str, Any] = {}

    # Extract IP layer
    ip_layer = None
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

    # 1. Check for IP Protocol 50 (ESP) directly on IP layer
    if ip_layer and getattr(ip_layer, "proto", None) == 50 or pkt.haslayer(ESP):
        is_esp = True
        proto_str = "ESP"
        # Extract ESP payload bytes
        esp_bytes = bytes(ip_layer.payload) if ip_layer else raw_bytes[14+20:]
        esp_info = parse_esp_header(esp_bytes, frame_num, timestamp)
        spi = esp_info.get("spi")
        detailed = esp_info
        summary = f"ESP (SPI: {spi}, Seq: {esp_info.get('sequence_number')})"

    # 2. Check for UDP layer (IKE on 500, NAT-T on 4500)
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
        udp_payload = bytes(udp_layer.payload)

        if src_port == 500 or dst_port == 500:
            is_ike = True
            ike_info = parse_ike_payload(udp_payload, frame_num)
            proto_str = ike_info.get("ike_version", "IKE")
            detailed = ike_info
            summary = f"{proto_str}: {ike_info.get('exchange_type', 'Handshake')} (Init SPI: {ike_info.get('initiator_spi')})"
            spi = ike_info.get("initiator_spi")

        elif src_port == 4500 or dst_port == 4500:
            is_natt = True
            natt_info = parse_natt_payload(udp_payload, frame_num, timestamp)
            proto_str = natt_info.get("protocol", "NAT-T")
            is_ike = natt_info.get("is_ike", False)
            is_esp = natt_info.get("is_esp", False)
            spi = natt_info.get("spi")
            summary = natt_info.get("summary", "NAT-Traversal Traffic")
            detailed = natt_info
        else:
            proto_str = "UDP"
            summary = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

    elif pkt.haslayer("TCP"):
        proto_str = "TCP"
        summary = f"TCP packet ({pkt_len} bytes)"

    return {
        "frame_number": frame_num,
        "timestamp": timestamp,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": proto_str,
        "length": pkt_len,
        "summary": summary,
        "is_ike": is_ike,
        "is_esp": is_esp,
        "is_natt": is_natt,
        "spi": spi,
        "raw_hex_preview": hex_preview,
        "detailed_json": detailed
    }
