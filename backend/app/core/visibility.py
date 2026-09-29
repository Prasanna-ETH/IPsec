"""
Visibility Classification Model for Sovereign IPsec Intelligence.

Strict Epistemic Principles:
- OBSERVED: Directly present in unencrypted packet headers (Confidence = 1.0)
- DERIVED: Deterministically calculated from multiple observations (Confidence = 1.0)
- INFERRED: Statistical / ML classifications with explicit confidence (< 1.0)
- UNOBSERVABLE: Information encrypted or unavailable from passive capture.
  Always explicit: "Unavailable from passive encrypted observation"
"""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

class EvidenceType(str, Enum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"
    UNOBSERVABLE = "UNOBSERVABLE"

class VisibilityStatement(BaseModel):
    field_name: str
    evidence_type: EvidenceType
    value: Optional[Any] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_frames: list[int] = Field(default_factory=list)
    explanation: Optional[str] = None
    is_observable: bool = True

    @classmethod
    def observed(cls, field_name: str, value: Any, frames: list[int], explanation: Optional[str] = None):
        return cls(
            field_name=field_name,
            evidence_type=EvidenceType.OBSERVED,
            value=value,
            confidence=1.0,
            source_frames=frames,
            explanation=explanation or "Directly extracted from unencrypted packet headers.",
            is_observable=True
        )

    @classmethod
    def derived(cls, field_name: str, value: Any, frames: list[int], explanation: str):
        return cls(
            field_name=field_name,
            evidence_type=EvidenceType.DERIVED,
            value=value,
            confidence=1.0,
            source_frames=frames,
            explanation=explanation,
            is_observable=True
        )

    @classmethod
    def inferred(cls, field_name: str, value: Any, confidence: float, frames: list[int], explanation: str):
        return cls(
            field_name=field_name,
            evidence_type=EvidenceType.INFERRED,
            value=value,
            confidence=max(0.0, min(1.0, confidence)),
            source_frames=frames,
            explanation=explanation,
            is_observable=True
        )

    @classmethod
    def unobservable(cls, field_name: str, explanation: Optional[str] = None):
        return cls(
            field_name=field_name,
            evidence_type=EvidenceType.UNOBSERVABLE,
            value=None,
            confidence=0.0,
            source_frames=[],
            explanation=explanation or "Unavailable from passive encrypted observation without private keys or PSK.",
            is_observable=False
        )

# Standard Unobservable Assertions
UNOBSERVABLE_ITEMS = {
    "esp_plaintext_payload": "ESP payload is protected by symmetric authenticated encryption. Inner application data cannot be inspected passively.",
    "inner_ip_addresses": "Inner IP headers are encapsulated within ESP payload and encrypted in Tunnel Mode.",
    "inner_transport_ports": "TCP/UDP port numbers of inner protected traffic are encrypted inside ESP payload.",
    "pre_shared_key": "Pre-Shared Keys (PSK) never transit in plaintext across the network.",
    "private_keys": "Private Diffie-Hellman or RSA/ECDSA keys remain strictly on cryptographic endpoints.",
    "ike_auth_protected_identities": "IKEv2 IKE_AUTH exchange protects endpoint identity payloads under the negotiated SK_e/SK_a keys.",
}
