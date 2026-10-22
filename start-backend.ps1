# Applies migrations and starts the API on http://127.0.0.1:8000  (docs: /docs)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\backend")
& .venv\Scripts\python.exe -m alembic upgrade head
& .venv\Scripts\python.exe -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --reload
