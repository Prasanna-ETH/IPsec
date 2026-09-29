@echo off
echo ============================================================
echo   OMEGA // Sovereign IPsec Security Intelligence Platform
echo   SIH26160 - National Technical Research Organisation (NTRO)
echo ============================================================

start "OMEGA Backend" powershell -NoExit -ExecutionPolicy Bypass -File "%~dp0run_backend.ps1"
start "OMEGA Frontend" powershell -NoExit -ExecutionPolicy Bypass -File "%~dp0run_frontend.ps1"

echo Backend and Frontend instances started.
