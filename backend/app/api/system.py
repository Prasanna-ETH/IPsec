import shutil
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.models import Capture, Tunnel
from app.schemas.schemas import SystemStatusResponse
from app.core.config import settings
from app.engines.rule_engine import RuleEngine

router = APIRouter(prefix="", tags=["System"])
rule_engine = RuleEngine()

@router.get("/system/status", response_model=SystemStatusResponse)
def get_system_status(db: Session = Depends(get_db)):
    tshark_path = shutil.which("tshark")
    caps_count = db.query(Capture).count()
    tunnels_count = db.query(Tunnel).count()

    return SystemStatusResponse(
        project_name=settings.PROJECT_NAME,
        project_subtitle=settings.PROJECT_SUBTITLE,
        version=settings.VERSION,
        rulepack_version=settings.RULEPACK_VERSION,
        ml_model_version=settings.ML_MODEL_VERSION,
        deployment_mode="AIR-GAPPED / LOCAL",
        external_apis="DISABLED",
        cloud_analysis="NONE",
        telemetry="DISABLED",
        analysis_engine="ONLINE (LOCAL SOVEREIGN PIPELINE)",
        rule_engine=f"ACTIVE ({len(rule_engine.rules)} Rules Loaded)",
        ml_model_status="LOCAL XGBOOST BEHAVIORAL CLASSIFIER READY",
        database_status="SQLITE LOCAL EMBEDDED (READY FOR POSTGRES)",
        tshark_available=bool(tshark_path),
        active_captures_count=caps_count,
        active_tunnels_count=tunnels_count,
        active_rules_count=len(rule_engine.rules)
    )

@router.get("/rules")
def get_rules():
    """Returns all loaded YAML deterministic rules."""
    return {
        "rulepack_version": settings.RULEPACK_VERSION,
        "total_rules": len(rule_engine.rules),
        "rules": rule_engine.rules
    }
