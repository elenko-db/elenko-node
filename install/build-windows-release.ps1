#Requires -Version 5.1
<#
.SYNOPSIS
  Build elenko-<version>-win-x64.zip for distribution (run on a dev machine with the full repo).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install\build-windows-release.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install\build-windows-release.ps1 -OutputDir dist
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "dist",
    [string]$RepoRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$packageJsonPath = Join-Path $RepoRoot "package.json"
if (-not (Test-Path -LiteralPath $packageJsonPath)) {
    throw "package.json not found in $RepoRoot"
}

$package = Get-Content -LiteralPath $packageJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
$version = [string]$package.version
$archiveBaseName = "elenko-$version-win-x64"
$stagingRoot = Join-Path $env:TEMP ("elenko-release-" + [Guid]::NewGuid().ToString("N"))
$stageDir = Join-Path $stagingRoot $archiveBaseName
$outDir = Join-Path $RepoRoot $OutputDir
$zipPath = Join-Path $outDir "$archiveBaseName.zip"

Write-Host ""
Write-Host "Elenko Windows release build" -ForegroundColor White
Write-Host "Version: $version"
Write-Host "Output:  $zipPath"
Write-Host ""

Write-Step "Staging files"
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

$excludeDirs = @(
    "node_modules",
    ".git",
    "dist",
    "logs",
    ".cursor"
)
$excludeFiles = @(
    ".env",
    "test-write.tmp",
    "_pk_fragment.js",
    "_pk_add_index.js"
)

$robocopyArgs = @(
    $RepoRoot,
    $stageDir,
    "/E",
    "/NFL", "/NDL", "/NJH", "/NJS", "/NC", "/NS"
)
foreach ($dir in $excludeDirs) {
    $robocopyArgs += "/XD"
    $robocopyArgs += $dir
}
foreach ($file in $excludeFiles) {
    $robocopyArgs += "/XF"
    $robocopyArgs += $file
}

& robocopy @robocopyArgs | Out-Null
$robocopyExit = $LASTEXITCODE
if ($robocopyExit -ge 8) {
    throw "robocopy failed with exit code $robocopyExit"
}

Write-Step "Creating ZIP archive"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($stageDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

Write-Step "Cleaning up staging directory"
Remove-Item -LiteralPath $stagingRoot -Recurse -Force

$zipInfo = Get-Item -LiteralPath $zipPath
Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "  $($zipInfo.FullName)"
Write-Host "  $([math]::Round($zipInfo.Length / 1MB, 2)) MB"
Write-Host ""
Write-Host "On the target PC:"
Write-Host "  1. Extract the ZIP to e.g. C:\Elenko"
Write-Host "  2. Install Node.js 20 LTS and CouchDB 3.x"
Write-Host "  3. Run: powershell -ExecutionPolicy Bypass -File C:\Elenko\install\install-windows.ps1"
Write-Host ""
