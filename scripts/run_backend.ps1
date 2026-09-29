Set-Location -Path "$PSScriptRoot\..\backend"
Write-Host "[OMEGA] Starting Sovereign IPsec FastAPI Analysis Backend on http://127.0.0.1:8000 ..." -ForegroundColor Cyan
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
