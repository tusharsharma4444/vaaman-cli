# ─────────────────────────────────────────────
# Vaaman AI — Two-Step Launcher
# Step 1: Build + start backend in Docker
# Step 2: Start dashboard dev server
#
# Usage:
#   .\start.ps1              # Full start
#   .\start.ps1 -BackendOnly # Docker only, no dashboard
# ─────────────────────────────────────────────

param([switch]$BackendOnly)

Write-Host "▲ VAAMAN — Starting..." -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Docker backend ──────────────────
Write-Host "[1/2] Building Docker image..." -ForegroundColor Gray
docker compose down 2>$null
docker compose build

Write-Host "[1/2] Starting container..." -ForegroundColor Gray
docker compose up -d

Write-Host "[1/2] Waiting for API..." -ForegroundColor Gray
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Seconds 2
  try {
    $r = Invoke-RestMethod -Uri "http://localhost:3001/api/health" -TimeoutSec 2
    if ($r.status -eq 'ok') { $ready = $true; break }
  } catch { }
}
if (-not $ready) {
  Write-Host "API failed to start. Check: docker compose logs vaaman" -ForegroundColor Red
  exit 1
}

Write-Host ""
Write-Host "  ✔ Backend running" -ForegroundColor Green
Write-Host "  API:       http://localhost:3001" -ForegroundColor Green
Write-Host "  Dashboard: http://localhost:3001 (production build)" -ForegroundColor Green
Write-Host "  Events:    http://localhost:3001/api/events" -ForegroundColor Green
Write-Host ""

# ── Step 2: Dashboard (optional) ────────────
if (-not $BackendOnly) {
  Write-Host "[2/2] Starting Dashboard dev server..." -ForegroundColor Gray
  Write-Host "  Live dev:  http://localhost:5173" -ForegroundColor Cyan
  Write-Host ""
  npm run dev:dashboard
}
