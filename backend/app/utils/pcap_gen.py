"""
Realistic IPsec PCAP Generator for Testing, Validation, and Demonstrations.
Generates compliant and legacy IPsec network captures locally using Scapy.
"""

import os
import struct
import time
from typing import Any
from pathlib import Path
from scapy.all import wrpcap, Ether, IP, UDP, Raw

SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "sample_captures"
SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

def create_ikev2_sa_init_packet(src_ip: str, dst_ip: str, init_spi: bytes, resp_spi: bytes, is_resp: bool = False, msg_id: int = 0) -> Any:
    # Build IKEv2 Header (28 bytes)
    # init_spi(8), resp_spi(8), next_payload(33=SA), ver(0x20=IKEv2), exch(34=IKE_SA_INIT), flags, msg_id(4), length(4)
    flags = 0x20 if is_resp else 0x08
    
    # SA Payload Body:
    # Proposal 1: ENCR=AES-GCM-16 (28), PRF=SHA256 (5), INTEG=NONE (0), DH=Group 19 (19)
    # Transform 1: ENCR=28 (AES-GCM-16), Key length attr = 256
    t1 = struct.pack("!BBHH", 3, 0, 12, 1) + struct.pack("!HH", 28, 0) + struct.pack("!HH", 0x800E, 256)
    # Transform 2: PRF=5 (PRF_HMAC_SHA2_256)
    t2 = struct.pack("!BBHH", 3, 0, 8, 2) + struct.pack("!HH", 5, 0)
    # Transform 3: INTEG=0 (NONE)
    t3 = struct.pack("!BBHH", 3, 0, 8, 3) + struct.pack("!HH", 0, 0)
    # Transform 4: DH=19 (ECP-256)
    t4 = struct.pack("!BBHH", 0, 0, 8, 4) + struct.pack("!HH", 19, 0)
    
    transforms = t1 + t2 + t3 + t4
    prop_len = 8 + len(transforms)
    proposal = struct.pack("!BBHBBBB", 0, 0, prop_len, 1, 1, 0, 4) + transforms
    
    sa_payload_len = 4 + len(proposal)
    sa_payload = struct.pack("!BBH", 34, 0, sa_payload_len) + proposal  # next_payload=34(KE)
    
    # KE Payload (Group 19, 64 bytes)
    ke_body = struct.pack("!HH", 19, 0) + (b"\x11" * 64)
    ke_payload_len = 4 + len(ke_body)
    ke_payload = struct.pack("!BBH", 40, 0, ke_payload_len) + ke_body  # next_payload=40(Nonce)
    
    # Nonce Payload (32 bytes)
    nonce_body = b"\x22" * 32
    nonce_payload_len = 4 + len(nonce_body)
    nonce_payload = struct.pack("!BBH", 0, 0, nonce_payload_len) + nonce_body  # next_payload=0
    
    all_payloads = sa_payload + ke_payload + nonce_payload
    total_ike_len = 28 + len(all_payloads)
    
    ike_hdr = init_spi + resp_spi + bytes([33, 0x20, 34, flags]) + struct.pack("!II", msg_id, total_ike_len)
    ike_data = ike_hdr + all_payloads
    
    sport = 500
    dport = 500
    return Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=ike_data)

def create_esp_packet(src_ip: str, dst_ip: str, spi: int, seq: int, payload_len: int = 1200) -> Any:
    # IP Protocol 50 ESP packet
    # SPI (4 bytes) + Seq (4 bytes) + encrypted payload + ICV tag
    esp_data = struct.pack("!II", spi, seq) + (b"\x5a" * payload_len) + (b"\xaa" * 16)
    return Ether() / IP(src=src_ip, dst=dst_ip, proto=50) / Raw(load=esp_data)

def create_natt_packet(src_ip: str, dst_ip: str, spi: int, seq: int, payload_len: int = 800) -> Any:
    # UDP 4500 ESP encapsulation (first 4 bytes is non-zero SPI)
    esp_data = struct.pack("!II", spi, seq) + (b"\x5a" * payload_len) + (b"\xaa" * 16)
    return Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=4500, dport=4500) / Raw(load=esp_data)

def generate_sample_captures():
    base_time = time.time() - 3600

    # 1. Generate Hardened IKEv2 Capture (Compliant)
    p_ikev2 = []
    src = "192.168.10.10"
    dst = "192.168.20.20"
    init_spi = b"\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81"
    resp_spi = b"\x88\x77\x66\x55\x44\x33\x22\x11"

    # IKE_SA_INIT Request
    pkt1 = create_ikev2_sa_init_packet(src, dst, init_spi, b"\x00"*8, False, 0)
    pkt1.time = base_time
    p_ikev2.append(pkt1)

    # IKE_SA_INIT Response
    pkt2 = create_ikev2_sa_init_packet(dst, src, init_spi, resp_spi, True, 0)
    pkt2.time = base_time + 0.05
    p_ikev2.append(pkt2)

    # ESP Flow (AES-GCM compliant, bidirectional)
    spi_out = 0xc0ffee01
    spi_in = 0xc0ffee02
    for seq in range(1, 60):
        # Outbound packet
        p_out = create_esp_packet(src, dst, spi_out, seq, 1280)
        p_out.time = base_time + 0.1 + (seq * 0.02)
        p_ikev2.append(p_out)

        # Inbound packet
        p_in = create_esp_packet(dst, src, spi_in, seq, 200)
        p_in.time = base_time + 0.11 + (seq * 0.02)
        p_ikev2.append(p_in)

    file_hardened = SAMPLE_DIR / "ikev2_hardened_aes_gcm.pcap"
    wrpcap(str(file_hardened), p_ikev2)
    print(f"[PCAP Gen] Generated {file_hardened}")

    # 2. Generate Legacy IKEv1 3DES capture with sequence anomalies
    p_legacy = []
    src_l = "10.0.1.50"
    dst_l = "10.0.2.100"
    init_spi_l = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11"
    
    # Simple IKEv1 Aggressive exchange
    ike1_hdr = init_spi_l + (b"\x00"*8) + bytes([1, 0x10, 5, 0x00]) + struct.pack("!II", 0, 120)
    ike1_payload = ike1_hdr + (b"\x00" * 92)
    pkt_l1 = Ether() / IP(src=src_l, dst=dst_l) / UDP(sport=500, dport=500) / Raw(load=ike1_payload)
    pkt_l1.time = base_time
    p_legacy.append(pkt_l1)

    # ESP Flow with gaps and replays
    spi_l = 0xdeadbeef
    seq_list = [1, 2, 3, 4, 7, 8, 9, 10, 10, 11, 15, 16, 17, 18, 25, 26, 27]
    for idx, seq in enumerate(seq_list):
        p_esp = create_esp_packet(src_l, dst_l, spi_l, seq, 1400)
        p_esp.time = base_time + 0.2 + (idx * 0.01)
        p_legacy.append(p_esp)

    file_legacy = SAMPLE_DIR / "ikev1_legacy_3des_sha1.pcap"
    wrpcap(str(file_legacy), p_legacy)
    print(f"[PCAP Gen] Generated {file_legacy}")

    # 3. Generate NAT-T capture
    p_natt = []
    src_n = "172.16.5.10"
    dst_n = "198.51.100.2"
    spi_n = 0x55aa55aa
    for seq in range(1, 40):
        pn = create_natt_packet(src_n, dst_n, spi_n, seq, 650)
        pn.time = base_time + (seq * 0.03)
        p_natt.append(pn)

    file_natt = SAMPLE_DIR / "natt_traversal_esp.pcap"
    wrpcap(str(file_natt), p_natt)
    print(f"[PCAP Gen] Generated {file_natt}")

if __name__ == "__main__":
    from typing import Any
    generate_sample_captures()
