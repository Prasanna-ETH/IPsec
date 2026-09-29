Write-Host "============================================================" -ForegroundColor Blue
Write-Host "  OMEGA // Sovereign IPsec Security Intelligence Platform" -ForegroundColor White
Write-Host "  SIH26160 | National Technical Research Organisation (NTRO)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Blue

# Launch Backend in new window
Start-Process powershell -ArgumentList "-NoExit", "-File", "$PSScriptRoot\run_backend.ps1"

# Launch Frontend in new window
Start-Process powershell -ArgumentList "-NoExit", "-File", "$PSScriptRoot\run_frontend.ps1"

Write-Host "Both Backend (http://127.0.0.1:8000) and Frontend (http://localhost:5173) are starting..." -ForegroundColor Green
