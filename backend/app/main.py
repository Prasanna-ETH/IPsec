from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.db.database import init_db
from app.api import captures, tunnels, findings, reports, compare, system

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite schema
    init_db()
    yield

app = FastAPI(
    title=f"{settings.PROJECT_NAME} - {settings.PROJECT_SUBTITLE}",
    version=settings.VERSION,
    description="Passive AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_origin_regex=r"^https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API v1 Routers
api_v1 = FastAPI()
api_v1.include_router(captures.router)
api_v1.include_router(tunnels.router)
api_v1.include_router(findings.router)
api_v1.include_router(reports.router)
api_v1.include_router(compare.router)
api_v1.include_router(system.router)

app.mount("/api/v1", api_v1)

@app.get("/health")
def health_check():
    return {
        "status": "HEALTHY",
        "service": settings.PROJECT_NAME,
        "mode": "AIR_GAPPED_LOCAL",
        "version": settings.VERSION
    }
