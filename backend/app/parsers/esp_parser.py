"""
ESP (Encapsulating Security Payload - IP Protocol 50) Parser.
Extracts unencrypted ESP header fields (SPI, Sequence Number, Length, Timing)
strictly from metadata without attempting payload decryption.
Follows RFC 4303.
"""

import struct
from typing import Any

def parse_esp_header(raw_bytes: bytes, frame_num: int, timestamp: float) -> dict[str, Any]:
    """
    Parses ESP header metadata from IP protocol 50 payload or UDP 4500 ESP payload.
    RFC 4303:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               Security Parameters Index (SPI)                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Sequence Number                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Payload Data  (variable)                   |
    """
    result: dict[str, Any] = {
        "is_esp": True,
        "spi": "0x00000000",
        "spi_int": 0,
        "sequence_number": 0,
        "payload_length": len(raw_bytes),
        "frame_number": frame_num,
        "timestamp": timestamp,
        "has_esn": False,  # Extended Sequence Numbers (inferred if rollover occurs)
    }

    if len(raw_bytes) < 8:
        return result

    try:
        spi_raw, seq_num = struct.unpack("!II", raw_bytes[0:8])
        result["spi"] = f"0x{spi_raw:08x}"
        result["spi_int"] = spi_raw
        result["sequence_number"] = seq_num
    except Exception as exc:
        result["parse_warning"] = str(exc)

    return result
