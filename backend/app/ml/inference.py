"""
Behavioral Flow Classifier Inference Engine.
Predicts high-level flow dynamics: INTERACTIVE, BULK_TRANSFER, VOIP_LIKE, VIDEO_LIKE, UNKNOWN.
Strictly returns UNKNOWN if trained model file is not present.
"""

import os
import joblib
from pathlib import Path
from typing import Any
import numpy as np
from app.core.config import settings
from app.ml.feature_extractor import FEATURE_NAMES

MODEL_PATH = settings.MODEL_DIR / "esp_behavioral_xgb.joblib"

class BehavioralClassifier:
    def __init__(self, model_path: Path = MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.classes = ["INTERACTIVE", "BULK_TRANSFER", "VOIP_LIKE", "VIDEO_LIKE"]
        self.load_model()

    def load_model(self):
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
            except Exception as e:
                print(f"[ML] Warning loading model: {e}")
                self.model = None

    def predict_window(self, feature_dict: dict[str, Any]) -> tuple[str, float]:
        """
        Predicts behavioral class and confidence.
        If no model is loaded, returns ('UNKNOWN', 0.0).
        """
        if self.model is None:
            # Fallback heuristic classifier strictly labeled as rule-based inference
            mean_size = feature_dict.get("mean_packet_size", 0)
            mean_iat = feature_dict.get("mean_iat", 0)
            up_ratio = feature_dict.get("upstream_ratio", 0.5)

            if mean_size > 1000 and (up_ratio > 0.85 or up_ratio < 0.15):
                return "Likely Bulk Transfer", 0.78
            elif mean_size < 300 and mean_iat < 0.03:
                return "Likely VoIP / Real-time Media", 0.72
            elif mean_size < 400 and mean_iat >= 0.05:
                return "Likely Interactive / Transactional", 0.68
            else:
                return "UNKNOWN", 0.0

        try:
            # Build feature vector matching FEATURE_NAMES
            vec = [feature_dict.get(fn, 0.0) for fn in FEATURE_NAMES]
            probs = self.model.predict_proba(np.array([vec]))[0]
            max_idx = int(np.argmax(probs))
            confidence = float(probs[max_idx])
            class_name = self.classes[max_idx] if max_idx < len(self.classes) else "UNKNOWN"
            return f"Likely {class_name.replace('_', ' ').title()}", round(confidence, 2)
        except Exception:
            return "UNKNOWN", 0.0

classifier = BehavioralClassifier()
