#Requires -Version 5.1
<#
.SYNOPSIS
  Upgrade Elenko after extracting a newer release ZIP over the install folder.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install\upgrade-windows.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "",
    [string]$TaskName = "Elenko"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

if (-not $InstallDir) {
    $InstallDir = Split-Path -Parent $PSScriptRoot
}
$InstallDir = (Resolve-Path -LiteralPath $InstallDir).Path

Write-Host ""
Write-Host "Elenko Windows upgrade" -ForegroundColor White
Write-Host "Install directory: $InstallDir"
Write-Host ""

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Write-Step "Stopping scheduled task '$TaskName'"
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}

Write-Step "Refreshing npm dependencies"
Push-Location -LiteralPath $InstallDir
try {
    & npm ci --omit=dev
    if ($LASTEXITCODE -ne 0) {
        throw "npm ci failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

if ($task) {
    Write-Step "Starting scheduled task '$TaskName'"
    Start-ScheduledTask -TaskName $TaskName
}

Write-Host ""
Write-Host "Upgrade complete. Restart Elenko if it was running manually (npm start)." -ForegroundColor Green
Write-Host ""
