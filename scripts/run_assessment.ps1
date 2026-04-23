<#
Launches Soun Al Hosn Assessment Runner from an installed Windows location.
All mutable paths are external to the application directory.
#>

[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\SounRunner",
    [string]$ConfigPath = "",
    [string]$DataDir = "",
    [string]$LogDir = "",
    [string]$ExePath = "",
    [switch]$Sample,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RunnerArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $InstallRoot "config\config.yaml"
}
if (-not $DataDir) {
    $DataDir = Join-Path $InstallRoot "data"
}
if (-not $LogDir) {
    $LogDir = Join-Path $InstallRoot "logs"
}
if (-not $ExePath) {
    $ExePath = Join-Path $InstallRoot "app\SounAlHosnAssessmentRunner.exe"
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ConfigPath) | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

if (-not (Test-Path $ConfigPath)) {
    $exampleConfig = Join-Path $InstallRoot "app\config.example.yaml"
    if (Test-Path $exampleConfig) {
        Copy-Item -Path $exampleConfig -Destination $ConfigPath -Force
    }
    else {
        throw "Config file missing and no example config found: $ConfigPath"
    }
}

if (-not (Test-Path $ExePath)) {
    throw "Runner executable not found: $ExePath"
}

$arguments = @(
    "--config", $ConfigPath,
    "--data-dir", $DataDir,
    "--log-dir", $LogDir
)

if ($Sample) {
    $arguments += "--sample"
}
if ($RunnerArgs) {
    $arguments += $RunnerArgs
}

Write-Host "Launching Soun Al Hosn Assessment Runner..."
Write-Host "Data: $DataDir"
Write-Host "Logs: $LogDir"
& $ExePath @arguments
exit $LASTEXITCODE
