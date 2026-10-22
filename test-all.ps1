# Runs every check: backend lint + tests (SQLite, no Docker needed) and frontend typecheck + tests + build
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
Push-Location backend
& .venv\Scripts\python.exe -m ruff check .
& .venv\Scripts\python.exe -m ruff format --check .
& .venv\Scripts\python.exe -m pytest -q
Pop-Location
Push-Location frontend
npm run typecheck
npm test
npm run build
Pop-Location
Write-Host "All checks passed."
