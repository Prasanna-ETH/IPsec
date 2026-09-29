"""
Session and Tunnel Aggregation Engine.
Groups raw packet metadata into bidirectional IPsec tunnels, IKE handshakes,
and unidirectional/bidirectional ESP Security Associations.
"""

from typing import Any
import math

def build_sessions_and_tunnels(packet_records: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Groups packets into Tunnels, IKE Sessions, and ESP SAs.
    """
    tunnels_map: dict[str, dict[str, Any]] = {}

    for pkt in packet_records:
        src = pkt["source_ip"]
        dst = pkt["destination_ip"]

        if src == "UNKNOWN" or dst == "UNKNOWN":
            continue

        # Canonical tunnel key (sorted endpoints)
        endpoints = sorted([src, dst])
        tunnel_key = f"{endpoints[0]}<->{endpoints[1]}"

        if tunnel_key not in tunnels_map:
            tunnels_map[tunnel_key] = {
                "tunnel_key": tunnel_key,
                "endpoint_a": endpoints[0],
                "endpoint_b": endpoints[1],
                "first_seen": pkt["timestamp"],
                "last_seen": pkt["timestamp"],
                "packet_count": 0,
                "byte_count": 0,
                "ike_version": None,
                "natt_enabled": False,
                "ike_sessions": {},
                "esp_sas": {},
                "packets": [],
            }

        t = tunnels_map[tunnel_key]
        t["packet_count"] += 1
        t["byte_count"] += pkt["length"]
        t["last_seen"] = max(t["last_seen"], pkt["timestamp"])
        t["first_seen"] = min(t["first_seen"], pkt["timestamp"])
        t["packets"].append(pkt)

        if pkt.get("is_natt"):
            t["natt_enabled"] = True

        # Process IKE packets
        if pkt.get("is_ike") and pkt.get("detailed_json"):
            ike_data = pkt["detailed_json"]
            ver = ike_data.get("ike_version")
            if ver and ver != "UNKNOWN":
                t["ike_version"] = ver

            init_spi = ike_data.get("initiator_spi")
            resp_spi = ike_data.get("responder_spi")
            ike_key = f"{init_spi}_{resp_spi}"

            if ike_key not in t["ike_sessions"]:
                t["ike_sessions"][ike_key] = {
                    "initiator_spi": init_spi,
                    "responder_spi": resp_spi,
                    "ike_version": ver or "IKEv2",
                    "exchange_type": ike_data.get("exchange_type"),
                    "message_id": ike_data.get("message_id", 0),
                    "is_aggressive_mode": ike_data.get("is_aggressive_mode", False),
                    "first_seen": pkt["timestamp"],
                    "last_seen": pkt["timestamp"],
                    "packet_count": 0,
                    "proposals": []
                }

            ike_sess = t["ike_sessions"][ike_key]
            ike_sess["packet_count"] += 1
            ike_sess["last_seen"] = max(ike_sess["last_seen"], pkt["timestamp"])
            if ike_data.get("proposals"):
                ike_sess["proposals"].extend(ike_data["proposals"])

        # Process ESP packets
        if pkt.get("is_esp") and pkt.get("detailed_json"):
            esp_data = pkt["detailed_json"]
            spi = esp_data.get("spi") or pkt.get("spi")
            if spi and spi != "0x00000000":
                if spi not in t["esp_sas"]:
                    t["esp_sas"][spi] = {
                        "spi": spi,
                        "source_ip": src,
                        "destination_ip": dst,
                        "direction": "OUTBOUND" if src == endpoints[0] else "INBOUND",
                        "first_seen": pkt["timestamp"],
                        "last_seen": pkt["timestamp"],
                        "packet_count": 0,
                        "byte_count": 0,
                        "sequences": [],
                        "timestamps": [],
                        "packet_sizes": [],
                        "is_natt": pkt.get("is_natt", False),
                    }
                esp_sa = t["esp_sas"][spi]
                esp_sa["packet_count"] += 1
                esp_sa["byte_count"] += pkt["length"]
                esp_sa["last_seen"] = max(esp_sa["last_seen"], pkt["timestamp"])
                seq = esp_data.get("sequence_number", 0)
                if seq > 0:
                    esp_sa["sequences"].append(seq)
                esp_sa["timestamps"].append(pkt["timestamp"])
                esp_sa["packet_sizes"].append(pkt["length"])

    # Compute derived metrics per ESP SA and Tunnel
    for t_key, t in tunnels_map.items():
        t["duration"] = round(t["last_seen"] - t["first_seen"], 3)
        for spi, sa in t["esp_sas"].items():
            seqs = sa["sequences"]
            sa["min_seq"] = min(seqs) if seqs else 0
            sa["max_seq"] = max(seqs) if seqs else 0

            # Sequence gaps calculation
            gaps = 0
            replays = 0
            seen_seqs = set()
            for i in range(1, len(seqs)):
                diff = seqs[i] - seqs[i-1]
                if diff > 1:
                    gaps += (diff - 1)
                elif diff <= 0:
                    replays += 1
                seen_seqs.add(seqs[i])

            sa["sequence_gaps"] = gaps
            sa["replay_suspect_count"] = replays

            # Statistical packet metrics
            sizes = sa["packet_sizes"]
            if sizes:
                sa["mean_packet_size"] = round(sum(sizes) / len(sizes), 2)
                variance = sum((x - sa["mean_packet_size"]) ** 2 for x in sizes) / len(sizes)
                sa["std_packet_size"] = round(math.sqrt(variance), 2)
            else:
                sa["mean_packet_size"] = 0.0
                sa["std_packet_size"] = 0.0

            # Inter-arrival times (IAT)
            times = sa["timestamps"]
            if len(times) > 1:
                iats = [times[i] - times[i-1] for i in range(1, len(times))]
                sa["mean_iat"] = round(sum(iats) / len(iats), 5)
                variance_iat = sum((x - sa["mean_iat"]) ** 2 for x in iats) / len(iats)
                sa["std_iat"] = round(math.sqrt(variance_iat), 5)
                # Burst count: consecutive packets with IAT < 10ms
                sa["burst_count"] = sum(1 for iat in iats if iat < 0.01)
            else:
                sa["mean_iat"] = 0.0
                sa["std_iat"] = 0.0
                sa["burst_count"] = 0

            sa["direction_ratio"] = 1.0  # calculated across tunnel

    return tunnels_map
