"""
Explainable Risk Engine for OMEGA Platform.
Computes multi-dimensional risk posture:
C = Crypto Posture (Weight 0.35)
K = Key Management (Weight 0.25)
P = Protocol Compliance (Weight 0.20)
A = Statistical Anomaly (Weight 0.10)
M = Metadata Exposure (Weight 0.10)
Generates itemized mathematical breakdown of contributing risk factors.
"""

from typing import Any

WEIGHTS = {
    "crypto": 0.35,
    "key_mgmt": 0.25,
    "protocol": 0.20,
    "anomaly": 0.10,
    "metadata": 0.10,
}

SEVERITY_SCORES = {
    "CRITICAL": 35.0,
    "HIGH": 20.0,
    "MEDIUM": 10.0,
    "LOW": 4.0,
    "INFORMATIONAL": 0.0,
}

class RiskEngine:
    def __init__(self, weights: dict[str, float] = WEIGHTS):
        self.weights = weights

    def calculate_risk(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Calculates category scores and overall weighted risk score with contributors.
        """
        cat_scores = {
            "CRYPTO": 0.0,
            "KEY_MGMT": 0.0,
            "PROTOCOL": 0.0,
            "ANOMALY": 0.0,
            "METADATA": 0.0,
        }
        contributors = []

        for f in findings:
            cat = f.get("category", "PROTOCOL").upper()
            sev = f.get("severity", "MEDIUM").upper()
            conf = float(f.get("confidence", 1.0))
            base_score = SEVERITY_SCORES.get(sev, 5.0)
            
            # Weighted by confidence for inferred findings
            effective_pts = round(base_score * conf, 1)

            if cat in cat_scores:
                cat_scores[cat] = min(100.0, cat_scores[cat] + effective_pts)
            else:
                cat_scores["PROTOCOL"] = min(100.0, cat_scores["PROTOCOL"] + effective_pts)

            contributors.append({
                "finding_id": f.get("id"),
                "rule_id": f.get("rule_id"),
                "title": f.get("title"),
                "category": cat,
                "severity": sev,
                "points": effective_pts,
                "confidence": conf,
                "evidence_type": f.get("evidence_type", "OBSERVED")
            })

        # Sort contributors by points descending
        contributors.sort(key=lambda x: x["points"], reverse=True)

        c = cat_scores["CRYPTO"]
        k = cat_scores["KEY_MGMT"]
        p = cat_scores["PROTOCOL"]
        a = cat_scores["ANOMALY"]
        m = cat_scores["METADATA"]

        overall = (
            self.weights["crypto"] * c +
            self.weights["key_mgmt"] * k +
            self.weights["protocol"] * p +
            self.weights["anomaly"] * a +
            self.weights["metadata"] * m
        )
        overall = round(min(100.0, overall), 1)

        risk_level = "LOW"
        if overall >= 75.0:
            risk_level = "CRITICAL"
        elif overall >= 50.0:
            risk_level = "HIGH"
        elif overall >= 25.0:
            risk_level = "MEDIUM"
        elif overall > 0.0:
            risk_level = "LOW"
        else:
            risk_level = "INFORMATIONAL"

        return {
            "overall_score": overall,
            "risk_level": risk_level,
            "crypto_score": round(c, 1),
            "key_mgmt_score": round(k, 1),
            "protocol_score": round(p, 1),
            "anomaly_score": round(a, 1),
            "metadata_score": round(m, 1),
            "weights": self.weights,
            "contributors": contributors
        }
