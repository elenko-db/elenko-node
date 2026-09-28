#Requires -Version 5.1
<#
.SYNOPSIS
  Install Elenko on Windows (no Git required).

.DESCRIPTION
  Run from the extracted release folder after unzipping elenko-*-win-x64.zip.
  Requires Node.js 20+ and a running CouchDB 3.x instance.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install\install-windows.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install\install-windows.ps1 -RegisterStartupTask
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "",
    [switch]$RegisterStartupTask,
    [string]$TaskName = "Elenko",
    [int]$Port = 3000,
    [string]$CouchDbUrl = "http://admin:admin@127.0.0.1:5984",
    [string]$CouchDbName = "elenko",
    [string]$ConfigDbName = "elenko_config"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "    $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "    WARNING: $Message" -ForegroundColor Yellow
}

function Get-NodeMajorVersion {
    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    if (-not $nodeCmd) { return $null }
    $versionText = (& node -v 2>$null).Trim()
    if ($versionText -match '^v?(\d+)') {
        return [int]$Matches[1]
    }
    return $null
}

function New-RandomSecret {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes)
}

function Ensure-EnvFile {
    param(
        [string]$TargetPath,
        [string]$ExamplePath
    )

    if (Test-Path -LiteralPath $TargetPath) {
        Write-Ok ".env already exists (left unchanged): $TargetPath"
        return
    }

    if (-not (Test-Path -LiteralPath $ExamplePath)) {
        throw "Missing template: $ExamplePath"
    }

    $content = Get-Content -LiteralPath $ExamplePath -Raw -Encoding UTF8
    $secret = New-RandomSecret
    $content = $content -replace '(?m)^SESSION_SECRET=.*$', "SESSION_SECRET=$secret"
    if ($content -notmatch '(?m)^SESSION_SECRET=') {
        $content = $content.TrimEnd() + "`r`nSESSION_SECRET=$secret`r`n"
    }
    $content = $content -replace '(?m)^PORT=.*$', "PORT=$Port"
    $content = $content -replace '(?m)^COUCHDB_URL=.*$', "COUCHDB_URL=$CouchDbUrl"
    $content = $content -replace '(?m)^COUCHDB_DB=.*$', "COUCHDB_DB=$CouchDbName"
    $content = $content -replace '(?m)^ELENKO_CONFIG_DB=.*$', "ELENKO_CONFIG_DB=$ConfigDbName"

    Set-Content -LiteralPath $TargetPath -Value $content -Encoding UTF8 -NoNewline
    Write-Ok "Created .env from template: $TargetPath"
}

function Register-ElenkoStartupTask {
    param(
        [string]$AppDir,
        [string]$Name
    )

    $nodeCmd = (Get-Command node).Source
    $action = New-ScheduledTaskAction -Execute $nodeCmd -Argument "server.js" -WorkingDirectory $AppDir
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

    $existing = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false
    }

    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
    Write-Ok "Registered scheduled task '$Name' (starts at logon for $env:USERNAME)"
}

if (-not $InstallDir) {
    $InstallDir = Split-Path -Parent $PSScriptRoot
}
$InstallDir = (Resolve-Path -LiteralPath $InstallDir).Path

Write-Host ""
Write-Host "Elenko Windows install" -ForegroundColor White
Write-Host "Install directory: $InstallDir"
Write-Host ""

Write-Step "Checking Node.js"
$nodeMajor = Get-NodeMajorVersion
if (-not $nodeMajor) {
    throw "Node.js not found in PATH. Install Node.js 20 LTS from https://nodejs.org/ and reopen PowerShell."
}
if ($nodeMajor -lt 20) {
    throw "Node.js $nodeMajor found; Elenko requires Node.js 20 or newer."
}
Write-Ok "Node.js v$nodeMajor OK"

Write-Step "Installing npm dependencies (production)"
Push-Location -LiteralPath $InstallDir
try {
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir "package-lock.json"))) {
        throw "package-lock.json not found. Extract the full release ZIP into $InstallDir."
    }
    & npm ci --omit=dev
    if ($LASTEXITCODE -ne 0) {
        throw "npm ci failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
Write-Ok "Dependencies installed"

Write-Step "Creating data directories"
$logsDir = Join-Path $InstallDir "logs"
$ioDir = Join-Path $InstallDir "io"
New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
New-Item -ItemType Directory -Path $ioDir -Force | Out-Null
Write-Ok "logs/ and io/ ready"

Write-Step "Environment file"
$envExample = Join-Path $PSScriptRoot ".env.example"
$envFile = Join-Path $InstallDir ".env"
Ensure-EnvFile -TargetPath $envFile -ExamplePath $envExample

if ($RegisterStartupTask) {
    Write-Step "Registering startup task"
    Register-ElenkoStartupTask -AppDir $InstallDir -Name $TaskName
}

Write-Host ""
Write-Host "Install complete." -ForegroundColor Green
Write-Host ""
Write-Host "Prerequisites (install separately if needed):"
Write-Host "  - CouchDB 3.x on port 5984 (default user admin / password admin, or edit .env)"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Start CouchDB"
Write-Host "  2. Start Elenko:"
Write-Host "       cd `"$InstallDir`""
Write-Host "       npm start"
if ($RegisterStartupTask) {
    Write-Host "     (or log off/on to start via scheduled task '$TaskName')"
}
Write-Host "  3. Open http://localhost:$Port/setup to finish CouchDB bootstrap"
Write-Host ""
Write-Host "To upgrade later: extract a newer ZIP over this folder (keep .env and logs/), then run:"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$InstallDir\install\upgrade-windows.ps1`""
Write-Host ""
