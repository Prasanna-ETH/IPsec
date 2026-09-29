"""
Feature Extractor for Encrypted ESP Traffic Metadata.
Extracts windowed statistical features strictly from packet sizes,
timestamps, directions, and sequence gaps without payload inspection.
"""

from typing import Any
import math
import numpy as np

FEATURE_NAMES = [
    "packet_count",
    "byte_count",
    "mean_packet_size",
    "std_packet_size",
    "min_packet_size",
    "max_packet_size",
    "mean_iat",
    "std_iat",
    "min_iat",
    "max_iat",
    "upstream_ratio",
    "downstream_ratio",
    "burst_count",
    "mean_burst_length",
    "mean_burst_duration",
    "sequence_gap_count",
    "sequence_gap_rate",
    "size_bin_0_128",
    "size_bin_129_512",
    "size_bin_513_1024",
    "size_bin_1025_1500",
]

def extract_flow_features(packets: list[dict[str, Any]], window_sec: float = 5.0) -> list[dict[str, Any]]:
    """
    Extracts rolling window statistical feature vectors from ESP packet list.
    """
    if not packets:
        return []

    # Sort packets by timestamp
    sorted_pkts = sorted(packets, key=lambda p: p.get("timestamp", 0.0))
    start_ts = sorted_pkts[0]["timestamp"]
    end_ts = sorted_pkts[-1]["timestamp"]

    windows = []
    curr_start = start_ts
    window_idx = 0

    while curr_start <= end_ts:
        curr_end = curr_start + window_sec
        win_pkts = [p for p in sorted_pkts if curr_start <= p["timestamp"] < curr_end]
        
        if win_pkts:
            feats = compute_window_vector(win_pkts, curr_start, curr_end)
            feats["window_index"] = window_idx
            windows.append(feats)

        curr_start += (window_sec / 2.0)  # 50% overlap
        window_idx += 1

    return windows


def compute_window_vector(pkts: list[dict[str, Any]], start_time: float, end_time: float) -> dict[str, Any]:
    n = len(pkts)
    sizes = [p.get("length", 0) for p in pkts]
    total_bytes = sum(sizes)
    times = [p.get("timestamp", 0.0) for p in pkts]

    mean_size = float(np.mean(sizes)) if n > 0 else 0.0
    std_size = float(np.std(sizes)) if n > 0 else 0.0
    min_size = int(np.min(sizes)) if n > 0 else 0
    max_size = int(np.max(sizes)) if n > 0 else 0

    # Inter-arrival times
    if n > 1:
        iats = [times[i] - times[i-1] for i in range(1, n)]
        mean_iat = float(np.mean(iats))
        std_iat = float(np.std(iats))
        min_iat = float(np.min(iats))
        max_iat = float(np.max(iats))
        bursts = sum(1 for iat in iats if iat < 0.01)
    else:
        mean_iat = 0.0
        std_iat = 0.0
        min_iat = 0.0
        max_iat = 0.0
        bursts = 0

    # Direction counts
    first_src = pkts[0].get("source_ip")
    up_count = sum(1 for p in pkts if p.get("source_ip") == first_src)
    down_count = n - up_count
    up_ratio = round(up_count / max(1, n), 3)
    down_ratio = round(down_count / max(1, n), 3)

    # Sequence gaps
    seqs = [p.get("detailed_json", {}).get("sequence_number", 0) for p in pkts if p.get("is_esp")]
    seqs = [s for s in seqs if s > 0]
    gaps = 0
    if len(seqs) > 1:
        for i in range(1, len(seqs)):
            if seqs[i] - seqs[i-1] > 1:
                gaps += (seqs[i] - seqs[i-1] - 1)
    gap_rate = round(gaps / max(1, n), 4)

    # Size bins
    b0 = sum(1 for s in sizes if s <= 128) / max(1, n)
    b1 = sum(1 for s in sizes if 128 < s <= 512) / max(1, n)
    b2 = sum(1 for s in sizes if 512 < s <= 1024) / max(1, n)
    b3 = sum(1 for s in sizes if s > 1024) / max(1, n)

    return {
        "start_time": start_time,
        "end_time": end_time,
        "packet_count": n,
        "byte_count": total_bytes,
        "mean_packet_size": round(mean_size, 2),
        "std_packet_size": round(std_size, 2),
        "min_packet_size": min_size,
        "max_packet_size": max_size,
        "mean_iat": round(mean_iat, 5),
        "std_iat": round(std_iat, 5),
        "min_iat": round(min_iat, 5),
        "max_iat": round(max_iat, 5),
        "upstream_ratio": up_ratio,
        "downstream_ratio": down_ratio,
        "burst_count": bursts,
        "mean_burst_length": round(bursts / max(1, n), 2),
        "mean_burst_duration": round(mean_iat * bursts, 3),
        "sequence_gap_count": gaps,
        "sequence_gap_rate": gap_rate,
        "size_bin_0_128": round(b0, 3),
        "size_bin_129_512": round(b1, 3),
        "size_bin_513_1024": round(b2, 3),
        "size_bin_1025_1500": round(b3, 3),
    }
