#!/usr/bin/env sh
# Linux/macOS equivalent of test-all.ps1 (expects backend/.venv or an active virtualenv)
set -e
cd "$(dirname "$0")/.."
(cd backend && python -m ruff check . && python -m ruff format --check . && python -m pytest -q)
(cd frontend && npm run typecheck && npm test && npm run build)
