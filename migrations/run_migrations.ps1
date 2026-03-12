<#
.SYNOPSIS
    Apply pending SQL migrations to a PostgreSQL database.

.PARAMETER Environment
    dev (default), staging, or prod.
    Reads connection details from the matching [SECTION] in .env.

.EXAMPLE
    .\migrations\run_migrations.ps1
    .\migrations\run_migrations.ps1 -Environment dev
#>
param(
    [ValidateSet("dev", "staging", "prod")]
    [string]$Environment = "dev"
)

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir
$EnvFile    = Join-Path $RepoRoot ".env"

# ── Read .env (INI-style) ─────────────────────────────────────────────────
function Read-EnvSection {
    param([string]$Path, [string]$Section)
    $values = @{}
    if (-not (Test-Path $Path)) { return $values }

    $inSection = $false
    foreach ($line in Get-Content $Path) {
        if ($line -match '^\[(\w+)\]') {
            $inSection = ($Matches[1].ToUpper() -eq $Section.ToUpper())
        }
        elseif ($inSection -and $line -match '^([^#=\s][^=]*)=(.*)$') {
            $values[$Matches[1].Trim().ToUpper()] = $Matches[2].Trim()
        }
    }
    return $values
}

# Merge COMMON then environment-specific (env overrides common)
$common  = Read-EnvSection -Path $EnvFile -Section 'COMMON'
$envCfg  = Read-EnvSection -Path $EnvFile -Section $Environment
# Manual merge so duplicate keys don't throw
$cfg = @{}
foreach ($k in $common.Keys)  { $cfg[$k] = $common[$k] }
foreach ($k in $envCfg.Keys)  { $cfg[$k] = $envCfg[$k] }  # env wins

$dbHost  = if ($cfg['DB_HOST'])     { $cfg['DB_HOST'] }     else { 'localhost' }
$dbPort  = if ($cfg['DB_PORT'])     { $cfg['DB_PORT'] }     else { '5432' }
$dbName  = if ($cfg['DB_NAME'])     { $cfg['DB_NAME'] }     else { 'pcp' }
$dbUser  = if ($cfg['DB_USER'])     { $cfg['DB_USER'] }     else { 'pgadmin' }
$dbPass  = if ($cfg['DB_PASSWORD']) { $cfg['DB_PASSWORD'] } else { $cfg['DB-PASSWORD'] }

if (-not $dbPass) {
    $secure  = Read-Host "DB_PASSWORD not found in .env [$Environment] - enter password" -AsSecureString
    $bstr    = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $dbPass  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

if (-not $dbPass) {
    Write-Error "No DB password provided. Aborting."
    exit 1
}

# ── Locate psql ───────────────────────────────────────────────────────────
$psql = Get-Command psql -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if (-not $psql) {
    # Common PostgreSQL install paths on Windows
    $candidates = @(
        'C:\Program Files\PostgreSQL\17\bin\psql.exe',
        'C:\Program Files\PostgreSQL\16\bin\psql.exe',
        'C:\Program Files\PostgreSQL\15\bin\psql.exe',
        'C:\Program Files\PostgreSQL\14\bin\psql.exe'
    )
    $psql = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $psql) {
    Write-Error "psql not found. Install PostgreSQL client tools or add psql to PATH."
    exit 1
}

Write-Host "=== PCP Manager DB Migrations ===" -ForegroundColor Cyan
Write-Host "  Environment : $Environment"
Write-Host "  Host        : $dbHost`:$dbPort"
Write-Host "  Database    : $dbName"
Write-Host "  User        : $dbUser"
Write-Host "  psql        : $psql"
Write-Host ""

$env:PGPASSWORD = $dbPass
$psqlArgs = @("--host=$dbHost", "--port=$dbPort", "--username=$dbUser", "--dbname=$dbName", "--no-password")

# ── Ensure tracking table exists ──────────────────────────────────────────
$createTable = @"
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
"@
& $psql @psqlArgs -c $createTable
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to create schema_migrations table."; exit 1 }

# ── Run each migration file ───────────────────────────────────────────────
$sqlFiles = Get-ChildItem -Path $ScriptDir -Filter '*.sql' | Sort-Object Name
$applied  = 0
$skipped  = 0

foreach ($file in $sqlFiles) {
    $filename = $file.Name
    $count = (& $psql @psqlArgs -t -c "SELECT COUNT(*) FROM schema_migrations WHERE filename = '$filename';").Trim()

    if ($count -gt 0) {
        Write-Host "  [SKIP]  $filename (already applied)" -ForegroundColor DarkGray
        $skipped++
    }
    else {
        Write-Host "  [RUN]   $filename ..." -ForegroundColor Yellow
        & $psql @psqlArgs -f $file.FullName
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Migration failed: $filename"
            exit 1
        }
        & $psql @psqlArgs -c "INSERT INTO schema_migrations (filename) VALUES ('$filename');"
        Write-Host "  [DONE]  $filename" -ForegroundColor Green
        $applied++
    }
}

Write-Host ""
Write-Host "=== Migration complete: $applied applied, $skipped skipped ===" -ForegroundColor Cyan
$env:PGPASSWORD = ''
