# Starts the dashboard on http://localhost:5173 (proxies /api to the backend on port 8000)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\frontend")
npm run dev
