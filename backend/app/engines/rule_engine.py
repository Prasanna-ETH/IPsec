"""
Deterministic Security Rule Engine for OMEGA Platform.
Loads versioned YAML rule definitions and evaluates them against
parsed IPsec tunnels, IKE proposals, and ESP metadata.
Adheres strictly to RFC 8247, RFC 7296, RFC 9395, and NIST SP 800-77 Rev. 1.
"""

import os
import yaml
from pathlib import Path
from typing import Any
from app.core.config import settings
from app.core.visibility import EvidenceType

class RuleEngine:
    def __init__(self, rules_dir: Path = settings.RULES_DIR):
        self.rules_dir = rules_dir
        self.rules: list[dict[str, Any]] = []
        self.version = settings.RULEPACK_VERSION
        self.load_rules()

    def load_rules(self):
        """Loads all YAML rule files from the rules directory."""
        self.rules = []
        if not self.rules_dir.exists():
            return

        for rule_file in self.rules_dir.glob("*.yaml"):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "rules" in data:
                        for r in data["rules"]:
                            r["file_source"] = rule_file.name
                            self.rules.append(r)
            except Exception as e:
                print(f"[RuleEngine] Error loading {rule_file}: {e}")

    def evaluate(self, tunnel: dict[str, Any], capture_id: str) -> list[dict[str, Any]]:
        """
        Evaluates loaded rules against a single parsed tunnel context.
        Returns a list of Finding dicts.
        """
        findings: list[dict[str, Any]] = []

        # Gather context objects
        ike_sessions = tunnel.get("ike_sessions", {})
        esp_sas = tunnel.get("esp_sas", {})

        # Flatten proposals
        proposals: list[dict[str, Any]] = []
        for sess in ike_sessions.values():
            proposals.extend(sess.get("proposals", []))

        # Check tunnel-level rules (e.g. IKE version, NAT-T)
        for rule in self.rules:
            r_id = rule.get("id")
            cat = rule.get("category", "PROTOCOL")
            sev = rule.get("severity", "MEDIUM")
            ev_type = rule.get("evidence_type", "OBSERVED")
            cond = rule.get("condition", {})
            field = cond.get("field")
            op = cond.get("operator")
            values = cond.get("values", [])

            # 1. Evaluate IKE Version
            if field == "ike_version":
                t_ver = tunnel.get("ike_version")
                if t_ver and self._matches_condition(t_ver, op, values):
                    frames = [p.get("frame_number") for p in tunnel.get("packets", []) if p.get("is_ike")][:5]
                    findings.append(self._create_finding(
                        rule, capture_id, tunnel, frames,
                        f"Tunnel negotiated using deprecated {t_ver} protocol (RFC 9395)."
                    ))

            # 2. Evaluate Aggressive Mode
            elif field == "is_aggressive_mode":
                for sess in ike_sessions.values():
                    if sess.get("is_aggressive_mode"):
                        frames = [p.get("frame_number") for p in tunnel.get("packets", []) if p.get("is_ike")][:3]
                        findings.append(self._create_finding(
                            rule, capture_id, tunnel, frames,
                            "IKEv1 Aggressive Mode exchange detected (Exchange Type 5). Cleartext identity hashes observed."
                        ))
                        break

            # 3. Evaluate NAT-T enabled
            elif field == "natt_enabled":
                if tunnel.get("natt_enabled"):
                    frames = [p.get("frame_number") for p in tunnel.get("packets", []) if p.get("is_natt")][:3]
                    findings.append(self._create_finding(
                        rule, capture_id, tunnel, frames,
                        "UDP Port 4500 encapsulation active. Traffic traverses NAT gateway."
                    ))

            # 4. Evaluate Proposals (Encryption, PRF, Integrity, DH)
            elif field in ("encryption_alg", "integrity_alg", "prf_alg", "dh_group"):
                for prop in proposals:
                    prop_val = str(prop.get(field, ""))
                    if self._matches_condition(prop_val, op, values):
                        frame = prop.get("frame_number")
                        frames = [frame] if frame else []
                        findings.append(self._create_finding(
                            rule, capture_id, tunnel, frames,
                            f"IKE Proposal {prop.get('proposal_number')} specifies {field} = '{prop_val}' ({prop.get('assessment')})."
                        ))

            # 5. Evaluate ESP SA metrics (Sequence gaps, Replays, Skew)
            elif field == "sequence_gap_rate":
                for spi, sa in esp_sas.items():
                    pkt_count = sa.get("packet_count", 1)
                    gap_count = sa.get("sequence_gaps", 0)
                    gap_rate = gap_count / max(1, pkt_count)
                    if self._matches_condition(gap_rate, op, values):
                        frames = [p.get("frame_number") for p in tunnel.get("packets", []) if p.get("spi") == spi][:5]
                        findings.append(self._create_finding(
                            rule, capture_id, tunnel, frames,
                            f"ESP SA {spi} has {gap_count} missing sequence numbers out of {pkt_count} packets (Gap Rate: {gap_rate:.2%})."
                        ))

            elif field == "replay_suspect_count":
                for spi, sa in esp_sas.items():
                    replays = sa.get("replay_suspect_count", 0)
                    if self._matches_condition(replays, op, values):
                        frames = [p.get("frame_number") for p in tunnel.get("packets", []) if p.get("spi") == spi][:5]
                        findings.append(self._create_finding(
                            rule, capture_id, tunnel, frames,
                            f"ESP SA {spi} recorded {replays} suspected replayed or out-of-order sequence numbers."
                        ))

        # Deduplicate findings by rule_id and title
        unique_findings = []
        seen_keys = set()
        for f in findings:
            key = f"{f['rule_id']}_{f['title']}"
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        return unique_findings

    def _matches_condition(self, val: Any, op: str, values: list[Any]) -> bool:
        if op == "eq":
            return val in values or val == values[0] if values else False
        elif op == "in":
            return any(str(v).lower() in str(val).lower() for v in values)
        elif op == "contains":
            return any(str(v).lower() in str(val).lower() for v in values)
        elif op == "gt":
            try:
                return float(val) > float(values[0])
            except (ValueError, TypeError):
                return False
        return False

    def _create_finding(self, rule: dict[str, Any], capture_id: str, tunnel: dict[str, Any], frames: list[int], tech_evidence: str) -> dict[str, Any]:
        return {
            "capture_id": capture_id,
            "tunnel_id": tunnel.get("id"),
            "rule_id": rule.get("id", "IPSEC-GEN-001"),
            "title": rule.get("title", "Security Finding"),
            "severity": rule.get("severity", "MEDIUM"),
            "category": rule.get("category", "PROTOCOL"),
            "evidence_type": rule.get("evidence_type", "OBSERVED"),
            "description": rule.get("description", ""),
            "technical_evidence": tech_evidence,
            "frame_references": frames,
            "standards_reference": rule.get("standards_reference", "RFC 8247 / NIST SP 800-77 Rev. 1"),
            "recommendation": rule.get("recommendation", "Review IPsec security policy."),
            "confidence": 1.0 if rule.get("evidence_type") in ("OBSERVED", "DERIVED") else 0.85,
            "status": "OPEN",
            "evidence_items": [
                {
                    "frame_number": f_num,
                    "protocol": tunnel.get("ike_version") or "IPsec",
                    "field_path": rule.get("condition", {}).get("field", "header"),
                    "extracted_value": str(rule.get("condition", {}).get("values", "")),
                    "raw_bytes_hex": None,
                    "notes": tech_evidence
                } for f_num in frames[:3]
            ]
        }
