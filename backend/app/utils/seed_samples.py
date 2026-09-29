"""
Ingestion script for sample PCAPs into SQLite database.
"""

import os
import hashlib
from pathlib import Path
from app.db.database import init_db, SessionLocal
from app.models.models import Capture
from app.services.analysis_service import analysis_service
from app.core.config import settings

SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "sample_captures"

def seed_sample_captures():
    init_db()
    db = SessionLocal()

    sample_files = [
        "ikev1_legacy_3des_sha1.pcap",
        "ikev2_hardened_aes_gcm.pcap",
        "natt_traversal_esp.pcap",
    ]

    for sf in sample_files:
        src_path = SAMPLE_DIR / sf
        if not src_path.exists():
            print(f"[Seed] Skipping {sf} (not found)")
            continue

        # Check if already in DB
        with open(src_path, "rb") as f:
            content = f.read()
            sha256 = hashlib.sha256(content).hexdigest()
            file_size = len(content)

        existing = db.query(Capture).filter(Capture.sha256 == sha256).first()
        if existing:
            print(f"[Seed] Capture {sf} already ingested (ID: {existing.id})")
            continue

        # Copy to uploads
        dest_path = settings.UPLOAD_DIR / sf
        with open(dest_path, "wb") as f:
            f.write(content)

        capture = Capture(
            filename=sf,
            filepath=str(dest_path),
            file_size=file_size,
            sha256=sha256,
            status="PENDING",
            stage_progress=0,
            current_stage="Queued for initial analysis"
        )
        db.add(capture)
        db.commit()
        db.refresh(capture)

        print(f"[Seed] Processing {sf} (ID: {capture.id})...")
        analysis_service.process_capture(capture.id)
        print(f"[Seed] Successfully analyzed {sf}")

    db.close()

if __name__ == "__main__":
    seed_sample_captures()
