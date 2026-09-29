"""
Training script for XGBoost ESP Flow Behavioral Classifier.
"""

import os
import joblib
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from app.core.config import settings
from app.ml.feature_extractor import FEATURE_NAMES

def generate_synthetic_training_data(n_samples: int = 1000):
    np.random.seed(42)
    X = []
    y = []

    # 0: INTERACTIVE (ssh, rdp, shell) -> small packets, high IAT variance
    for _ in range(n_samples // 4):
        vec = [
            np.random.randint(10, 100),       # packet_count
            np.random.randint(2000, 20000),   # byte_count
            np.random.uniform(80, 250),       # mean_packet_size
            np.random.uniform(20, 80),        # std_packet_size
            64,                               # min_packet_size
            np.random.randint(300, 600),      # max_packet_size
            np.random.uniform(0.05, 0.5),     # mean_iat
            np.random.uniform(0.02, 0.2),     # std_iat
            0.001,                            # min_iat
            1.5,                              # max_iat
            np.random.uniform(0.4, 0.6),      # upstream_ratio
            np.random.uniform(0.4, 0.6),      # downstream_ratio
            np.random.randint(0, 5),          # burst_count
            np.random.uniform(0.0, 0.2),      # mean_burst_length
            np.random.uniform(0.0, 0.1),      # mean_burst_duration
            0, 0.0,                           # sequence gaps
            0.6, 0.3, 0.1, 0.0                # size bins
        ]
        X.append(vec)
        y.append(0)

    # 1: BULK_TRANSFER (file sync, backup, large transfer) -> large packets, low IAT, asymmetric
    for _ in range(n_samples // 4):
        vec = [
            np.random.randint(200, 1000),     # packet_count
            np.random.randint(200000, 1400000),# byte_count
            np.random.uniform(1100, 1450),    # mean_packet_size
            np.random.uniform(50, 150),       # std_packet_size
            64,                               # min_packet_size
            1500,                             # max_packet_size
            np.random.uniform(0.001, 0.008),  # mean_iat
            np.random.uniform(0.0005, 0.003), # std_iat
            0.0001,                           # min_iat
            0.05,                             # max_iat
            np.random.uniform(0.85, 0.98),    # upstream_ratio
            np.random.uniform(0.02, 0.15),    # downstream_ratio
            np.random.randint(20, 80),        # burst_count
            np.random.uniform(0.3, 0.7),      # mean_burst_length
            np.random.uniform(0.1, 0.5),      # mean_burst_duration
            np.random.randint(0, 3), 0.002,   # sequence gaps
            0.05, 0.05, 0.1, 0.8              # size bins
        ]
        X.append(vec)
        y.append(1)

    # 2: VOIP_LIKE (audio streams) -> small uniform packets, steady IAT (~20ms)
    for _ in range(n_samples // 4):
        vec = [
            np.random.randint(100, 300),      # packet_count
            np.random.randint(15000, 50000),  # byte_count
            np.random.uniform(140, 220),      # mean_packet_size
            np.random.uniform(5, 20),         # std_packet_size
            120,                              # min_packet_size
            260,                              # max_packet_size
            np.random.uniform(0.018, 0.022),  # mean_iat ~20ms
            np.random.uniform(0.001, 0.004),  # std_iat
            0.015,                            # min_iat
            0.025,                            # max_iat
            np.random.uniform(0.48, 0.52),    # upstream_ratio
            np.random.uniform(0.48, 0.52),    # downstream_ratio
            np.random.randint(0, 2),          # burst_count
            0.0, 0.0,
            0, 0.0,
            0.1, 0.9, 0.0, 0.0
        ]
        X.append(vec)
        y.append(2)

    # 3: VIDEO_LIKE (video conferences) -> large keyframes mixed with audio, medium burstiness
    for _ in range(n_samples // 4):
        vec = [
            np.random.randint(150, 500),      # packet_count
            np.random.randint(80000, 400000), # byte_count
            np.random.uniform(700, 1100),     # mean_packet_size
            np.random.uniform(300, 500),      # std_packet_size
            80,                               # min_packet_size
            1450,                             # max_packet_size
            np.random.uniform(0.005, 0.02),   # mean_iat
            np.random.uniform(0.005, 0.015),  # std_iat
            0.001,
            0.08,
            np.random.uniform(0.4, 0.6),
            np.random.uniform(0.4, 0.6),
            np.random.randint(10, 40),
            np.random.uniform(0.2, 0.5),
            np.random.uniform(0.05, 0.2),
            0, 0.0,
            0.2, 0.2, 0.3, 0.3
        ]
        X.append(vec)
        y.append(3)

    return np.array(X), np.array(y)

def train_and_save():
    X, y = generate_synthetic_training_data(2000)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.08,
        random_state=42,
        eval_metric="mlogloss"
    )
    model.fit(X_train, y_train)
    acc = model.score(X_test, y_test)
    print(f"[ML Train] XGBoost model trained. Test Accuracy: {acc:.4f}")

    settings.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    out_file = settings.MODEL_DIR / "esp_behavioral_xgb.joblib"
    joblib.dump(model, out_file)
    print(f"[ML Train] Saved model to {out_file}")

if __name__ == "__main__":
    train_and_save()
