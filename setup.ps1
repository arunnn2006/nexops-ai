# One-time setup for Windows 11 (PowerShell). Run from the project root:  .\scripts\setup.ps1
# NOTE: written for Windows but not executed in the build environment (Linux). See docs/BUILD_STATUS.md.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

python -m venv backend\.venv
& backend\.venv\Scripts\python.exe -m pip install --upgrade pip
& backend\.venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
& backend\.venv\Scripts\python.exe scripts\generate_env.py

Push-Location frontend
npm install
Pop-Location

Write-Host "Setup complete. Next: .\scripts\start-backend.ps1  (then .\scripts\start-frontend.ps1 in a second terminal)"
