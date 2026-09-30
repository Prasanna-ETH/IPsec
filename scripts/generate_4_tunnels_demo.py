"""
OMEGA — 4-Tunnel Comprehensive Multi-Scenario PCAP Generator
Generates a realistic, educational network trace containing 4 distinct IPsec tunnels:

  • Tunnel 1: Modern IKEv2 + AES-256-GCM + DH Group 19 (Compliant / Clean ESP)
  • Tunnel 2: Legacy IKEv1 Aggressive Mode + 3DES + MD5 + Sequence Gap (Non-Compliant)
  • Tunnel 3: Native ESP with Duplicate / Replayed Sequence Numbers (Anomaly)
  • Tunnel 4: NAT-Traversal Encapsulation (UDP Port 4500 ESP stream)

Saves directly to sample_captures/ for instant 1-click analysis in OMEGA.
"""

import os
import struct
import time
from pathlib import Path
from scapy.all import wrpcap, Ether, IP, UDP, Raw

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIRS = [
    BASE_DIR / "sample_captures",
    BASE_DIR / "backend" / "sample_captures"
]

for d in OUTPUT_DIRS:
    d.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------
# PACKET BUILDER HELPERS
# ------------------------------------------------------------

def create_ikev2_sa_init_packet(src_ip: str, dst_ip: str, init_spi: bytes, resp_spi: bytes, is_resp: bool = False, msg_id: int = 0):
    flags = 0x20 if is_resp else 0x08
    # Proposal: AES-GCM-256, PRF-SHA256, DH Group 19
    t1 = struct.pack("!BBHH", 3, 0, 12, 1) + struct.pack("!HH", 28, 0) + struct.pack("!HH", 0x800E, 256)
    t2 = struct.pack("!BBHH", 3, 0, 8, 2) + struct.pack("!HH", 5, 0)
    t3 = struct.pack("!BBHH", 3, 0, 8, 3) + struct.pack("!HH", 0, 0)
    t4 = struct.pack("!BBHH", 0, 0, 8, 4) + struct.pack("!HH", 19, 0)
    transforms = t1 + t2 + t3 + t4
    prop_len = 8 + len(transforms)
    proposal = struct.pack("!BBHBBBB", 0, 0, prop_len, 1, 1, 0, 4) + transforms
    sa_payload_len = 4 + len(proposal)
    sa_payload = struct.pack("!BBH", 34, 0, sa_payload_len) + proposal

    ke_body = struct.pack("!HH", 19, 0) + (b"\x11" * 64)
    ke_payload = struct.pack("!BBH", 40, 0, 4 + len(ke_body)) + ke_body

    nonce_body = b"\x22" * 32
    nonce_payload = struct.pack("!BBH", 0, 0, 4 + len(nonce_body)) + nonce_body

    all_payloads = sa_payload + ke_payload + nonce_payload
    total_ike_len = 28 + len(all_payloads)
    ike_hdr = init_spi + resp_spi + bytes([33, 0x20, 34, flags]) + struct.pack("!II", msg_id, total_ike_len)

    return Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=500, dport=500) / Raw(load=ike_hdr + all_payloads)


def create_ikev1_aggressive_packet(src_ip: str, dst_ip: str, init_spi: bytes, resp_spi: bytes):
    # IKEv1 Aggressive Mode Exchange (Exchange Type 4)
    ike1_hdr = init_spi + resp_spi + bytes([1, 0x10, 4, 0x00]) + struct.pack("!II", 0, 140)
    # Payload with 3DES-CBC (Transform ID 3), MD5 (Hash 1), DH Group 2 (Group 2)
    fake_payload = (b"\x00\x00\x00\x1c\x01\x01\x00\x01\x00\x00\x00\x14\x01\x01\x00\x01\x00\x00\x00\x0c\x01\x03\x00\x00\x80\x01\x00\x05") + (b"\xaa" * 100)
    return Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=500, dport=500) / Raw(load=ike1_hdr + fake_payload)


def create_esp_packet(src_ip: str, dst_ip: str, spi: int, seq: int, payload_len: int = 500):
    payload = bytes(((i * 31 + seq * 17) % 256) for i in range(payload_len))
    esp_data = struct.pack("!II", spi, seq) + payload + (b"\xcc" * 16)
    return Ether() / IP(src=src_ip, dst=dst_ip, proto=50) / Raw(load=esp_data)


def create_natt_packet(src_ip: str, dst_ip: str, spi: int, seq: int, payload_len: int = 700):
    payload = bytes(((i * 23 + seq * 19) % 256) for i in range(payload_len))
    esp_data = struct.pack("!II", spi, seq) + payload + (b"\xdd" * 16)
    return Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=4500, dport=4500) / Raw(load=esp_data)


def build_4_tunnel_capture():
    all_packets = []
    base_t = time.time() - 300.0

    print("=" * 65)
    print("GENERATING OMEGA 4-TUNNEL MULTI-SCENARIO PCAP")
    print("=" * 65)

    # ------------------------------------------------------------
    # TUNNEL 1: Compliant Modern IKEv2 + AES-GCM-256 + Group 19
    # ------------------------------------------------------------
    print("[+] Building Tunnel 1: Modern IKEv2 Compliant (10.10.1.1 <-> 10.10.1.2)")
    t1_src, t1_dst = "10.10.1.1", "10.10.1.2"
    t1_init_spi = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    t1_resp_spi = b"\x88\x77\x66\x55\x44\x33\x22\x11"

    pkt1 = create_ikev2_sa_init_packet(t1_src, t1_dst, t1_init_spi, b"\x00" * 8, False, 0)
    pkt1.time = base_t
    all_packets.append(pkt1)

    pkt2 = create_ikev2_sa_init_packet(t1_dst, t1_src, t1_init_spi, t1_resp_spi, True, 0)
    pkt2.time = base_t + 0.02
    all_packets.append(pkt2)

    # Bidirectional clean sequential ESP traffic
    for seq in range(1, 21):
        p_fwd = create_esp_packet(t1_src, t1_dst, 0x10000001, seq, 1200)
        p_fwd.time = base_t + 0.1 + (seq * 0.02)
        all_packets.append(p_fwd)

        p_rev = create_esp_packet(t1_dst, t1_src, 0x10000002, seq, 300)
        p_rev.time = base_t + 0.11 + (seq * 0.02)
        all_packets.append(p_rev)

    # ------------------------------------------------------------
    # TUNNEL 2: Legacy IKEv1 3DES-CBC + SHA1 + Group 2 with Sequence Gaps
    # ------------------------------------------------------------
    print("[+] Building Tunnel 2: Legacy IKEv1 3DES + Sequence Gaps (10.20.1.1 -> 10.20.1.2)")
    t2_src, t2_dst = "10.20.1.1", "10.20.1.2"
    t2_init_spi = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22"
    t2_resp_spi = b"\x22\x11\xff\xee\xdd\xcc\xbb\xaa"

    pkt_ike1 = create_ikev1_aggressive_packet(t2_src, t2_dst, t2_init_spi, t2_resp_spi)
    pkt_ike1.time = base_t + 1.0
    all_packets.append(pkt_ike1)

    # ESP with missing sequence numbers 4, 5, 11, 12 (Sequence Discontinuity)
    t2_sequences = [1, 2, 3, 6, 7, 8, 9, 10, 13, 14, 15]
    for idx, seq in enumerate(t2_sequences):
        p = create_esp_packet(t2_src, t2_dst, 0x20000001, seq, 950)
        p.time = base_t + 1.2 + (idx * 0.03)
        all_packets.append(p)

    # ------------------------------------------------------------
    # TUNNEL 3: Suspicious Sequence Duplication / Replay Anomaly
    # ------------------------------------------------------------
    print("[+] Building Tunnel 3: ESP Sequence Replay / Duplicates (10.30.1.1 -> 10.30.1.2)")
    t3_src, t3_dst = "10.30.1.1", "10.30.1.2"
    # Sequences with duplicate 3, duplicate 5, duplicate 8
    t3_sequences = [1, 2, 3, 3, 4, 5, 5, 6, 7, 8, 8, 9, 10]
    for idx, seq in enumerate(t3_sequences):
        p = create_esp_packet(t3_src, t3_dst, 0x30000001, seq, 600)
        p.time = base_t + 2.0 + (idx * 0.025)
        all_packets.append(p)

    # ------------------------------------------------------------
    # TUNNEL 4: NAT-Traversal UDP Port 4500 ESP
    # ------------------------------------------------------------
    print("[+] Building Tunnel 4: NAT-T UDP 4500 Encapsulation (10.40.1.1 -> 10.40.1.2)")
    t4_src, t4_dst = "10.40.1.1", "10.40.1.2"
    for seq in range(1, 26):
        p = create_natt_packet(t4_src, t4_dst, 0x40000001, seq, 850)
        p.time = base_t + 3.0 + (seq * 0.02)
        all_packets.append(p)

    # Sort all packets by timestamp chronologically
    all_packets.sort(key=lambda x: x.time)

    # Write to target files
    filename = "omega_4_tunnel_learning.pcap"
    for out_dir in OUTPUT_DIRS:
        target_path = out_dir / filename
        wrpcap(str(target_path), all_packets)
        print(f"[OK] Saved PCAP to: {target_path}")

    print("\n" + "=" * 65)
    print(f"COMPLETE: {len(all_packets)} packets written across 4 distinct VPN tunnels!")
    print("=" * 65)

if __name__ == "__main__":
    build_4_tunnel_capture()
