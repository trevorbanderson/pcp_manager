<#
.SYNOPSIS
    Launch PCP Manager Flask app for a given environment.

.PARAMETER Environment
    Target environment: dev (default), staging, or prod.

.PARAMETER Port
    Port to listen on. Defaults to 5000.

.EXAMPLE
    .\run.ps1
    .\run.ps1 dev
    .\run.ps1 staging
    .\run.ps1 prod
    .\run.ps1 dev -Port 8080
#>
param(
    [ValidateSet("dev", "development", "staging", "prod", "production")]
    [string]$Environment = "dev",

    [int]$Port = 5000
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python    = Join-Path $ScriptDir ".venv\Scripts\python.exe"
$AppPy     = Join-Path $ScriptDir "app.py"

if (-not (Test-Path $Python)) {
    Write-Error "Virtual environment not found at '$Python'. Run 'python -m venv .venv' first."
    exit 1
}

Write-Host "Starting PCP Manager  [env=$Environment  port=$Port]" -ForegroundColor Cyan

& $Python $AppPy $Environment --port $Port
