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
    [string]$CompanyName = "",
    [ValidateSet("", "basic", "standard", "advanced")]
    [string]$Package = "",
    [switch]$NonInteractive,
    [switch]$ConsentConfirmed,
    [switch]$Sample,
    [switch]$Preflight,
    [switch]$Healthcheck,
    [switch]$ShowQueue,
    [switch]$RetryCallbacks,
    [string]$ResendSession = "",
    [switch]$ShowCheatsheet,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RunnerArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Header = @"
███████╗ ██████╗ ██╗   ██╗███╗   ██╗     █████╗ ██╗         ██╗  ██╗ ██████╗ ███████╗███╗   ██╗
██╔════╝██╔═══██╗██║   ██║████╗  ██║    ██╔══██╗██║         ██║  ██║██╔═══██╗██╔════╝████╗  ██║
███████╗██║   ██║██║   ██║██╔██╗ ██║    ███████║██║         ███████║██║   ██║███████╗██╔██╗ ██║
╚════██║██║   ██║██║   ██║██║╚██╗██║    ██╔══██║██║         ██╔══██║██║   ██║╚════██║██║╚██╗██║
███████║╚██████╔╝╚██████╔╝██║ ╚████║    ██║  ██║███████╗    ██║  ██║╚██████╔╝███████║██║ ╚████║
╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝

 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝
"@
Write-Host $Header

if ($ShowCheatsheet) {
    Write-Host "Operator command cheatsheet"
    Write-Host "  Preflight:      .\run_assessment.ps1 -Preflight"
    Write-Host "  Healthcheck:    .\run_assessment.ps1 -Healthcheck"
    Write-Host "  Run Standard:    .\run_assessment.ps1 -CompanyName 'Client Name' -Package standard"
    Write-Host "  Headless:        .\run_assessment.ps1 -CompanyName 'Client Name' -Package standard -NonInteractive -ConsentConfirmed"
    Write-Host "  Run assessment: .\run_assessment.ps1"
    Write-Host "  Sample run:     .\run_assessment.ps1 -Sample"
    Write-Host "  Show queue:     .\run_assessment.ps1 -ShowQueue"
    Write-Host "  Retry queue:    .\run_assessment.ps1 -RetryCallbacks"
    Write-Host "  Resend session: .\run_assessment.ps1 -ResendSession <session-id>"
    exit 0
}

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
if ($CompanyName) {
    $arguments += @("--company-name", $CompanyName)
}
if ($Package) {
    $arguments += @("--package", $Package)
}
if ($NonInteractive) {
    $arguments += "--non-interactive"
}
if ($ConsentConfirmed) {
    $arguments += "--consent-confirmed"
}
if ($Preflight) {
    $arguments += "--preflight"
}
if ($Healthcheck) {
    $arguments += "--healthcheck"
}
if ($ShowQueue) {
    $arguments += "--show-queue"
}
if ($RetryCallbacks) {
    $arguments += "--retry-callbacks"
}
if ($ResendSession) {
    $arguments += @("--resend-session", $ResendSession)
}
if ($RunnerArgs) {
    $arguments += $RunnerArgs
}

Write-Host "Launching Soun Al Hosn Assessment Runner..."
Write-Host "Data: $DataDir"
Write-Host "Logs: $LogDir"
& $ExePath @arguments
exit $LASTEXITCODE
