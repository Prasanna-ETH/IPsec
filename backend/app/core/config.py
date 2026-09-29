import os
import json
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    PROJECT_NAME: str = "OMEGA"
    PROJECT_SUBTITLE: str = "Sovereign IPsec Security Intelligence & Assessment Platform"
    VERSION: str = "1.0.0-SOVEREIGN"
    RULEPACK_VERSION: str = "2026.03.1-NIST-RFC"
    ML_MODEL_VERSION: str = "1.0.0-ESP-BEHAVIORAL"
    AIR_GAPPED: bool = True

    # Storage & paths
    BASE_DIR: Path = BASE_DIR
    UPLOAD_DIR: Path = BASE_DIR / "uploads"
    DATA_DIR: Path = BASE_DIR / "data"
    RULES_DIR: Path = BASE_DIR / "app" / "rules"
    MODEL_DIR: Path = BASE_DIR / "data" / "models"
    REPORTS_DIR: Path = BASE_DIR / "data" / "reports"

    # SQLite Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'data' / 'omega.db'}"

    # CORS — can be overridden via env var as JSON array string
    CORS_ORIGINS: str = '["http://localhost:5173","http://127.0.0.1:5173","http://localhost:3000","http://localhost:8000"]'

    def get_cors_origins(self) -> list[str]:
        try:
            parsed = json.loads(self.CORS_ORIGINS)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass
        return [self.CORS_ORIGINS]

    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()

# Ensure directories exist
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.MODEL_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
