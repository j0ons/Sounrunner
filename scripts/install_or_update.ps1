<#
Installs or updates Soun Al Hosn Assessment Runner from GitHub.

Default path:
  C:\SounRunner\app     - replaceable application files
  C:\SounRunner\config  - preserved configuration
  C:\SounRunner\data    - preserved evidence, reports, sessions, bundles
  C:\SounRunner\logs    - preserved logs

Release ZIPs are the approved distribution path. GitHub Actions artifacts are
supported for internal testing but usually require a GitHub token and expire.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Repository,

    [string]$InstallRoot = "C:\SounRunner",
    [string]$Version = "latest",
    [string]$AssetNamePattern = "SounAlHosnAssessmentRunner-windows*.zip",

    [switch]$UseActionsArtifact,
    [string]$ArtifactName = "soun-runner-windows",
    [string]$Branch = "main",

    [string]$GitHubToken = $env:GITHUB_TOKEN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Get-GitHubHeaders {
    $headers = @{
        "Accept" = "application/vnd.github+json"
        "User-Agent" = "SounRunnerInstaller"
        "X-GitHub-Api-Version" = "2022-11-28"
    }
    if ($GitHubToken) {
        $headers["Authorization"] = "Bearer $GitHubToken"
    }
    return $headers
}

function Invoke-GitHubJson {
    param([Parameter(Mandatory = $true)][string]$Uri)
    Invoke-RestMethod -Uri $Uri -Headers (Get-GitHubHeaders) -Method Get
}

function Save-RemoteFile {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [switch]$UseAuth
    )

    $headers = if ($UseAuth) {
        $authHeaders = Get-GitHubHeaders
        $authHeaders["Accept"] = "application/octet-stream"
        $authHeaders
    }
    else {
        @{"User-Agent" = "SounRunnerInstaller"}
    }
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -Headers $headers
}

function Get-ReleaseAssetDownload {
    if ($Version -eq "latest") {
        $release = Invoke-GitHubJson "https://api.github.com/repos/$Repository/releases/latest"
    }
    else {
        $release = Invoke-GitHubJson "https://api.github.com/repos/$Repository/releases/tags/$Version"
    }

    $asset = @($release.assets) | Where-Object { $_.name -like $AssetNamePattern } | Select-Object -First 1
    if (-not $asset) {
        throw "No release asset matching '$AssetNamePattern' found for $Repository version '$Version'."
    }
    if ($GitHubToken) {
        return [pscustomobject]@{
            Uri = $asset.url
            UseAuth = $true
        }
    }
    return [pscustomobject]@{
        Uri = $asset.browser_download_url
        UseAuth = $false
    }
}

function Get-ActionsArtifactUrl {
    if (-not $GitHubToken) {
        throw "Actions artifact download requires GITHUB_TOKEN or -GitHubToken. Use release ZIPs for client installs."
    }

    $encodedName = [uri]::EscapeDataString($ArtifactName)
    $artifacts = Invoke-GitHubJson "https://api.github.com/repos/$Repository/actions/artifacts?name=$encodedName"
    $artifact = @($artifacts.artifacts) |
        Where-Object { -not $_.expired -and $_.workflow_run.head_branch -eq $Branch } |
        Sort-Object -Property created_at -Descending |
        Select-Object -First 1
    if (-not $artifact) {
        throw "No non-expired Actions artifact named '$ArtifactName' found on branch '$Branch'."
    }
    return $artifact.archive_download_url
}

function Find-RunnerExe {
    param([Parameter(Mandatory = $true)][string]$Root)
    $exe = Get-ChildItem -Path $Root -Filter "SounAlHosnAssessmentRunner.exe" -Recurse -File |
        Select-Object -First 1
    if (-not $exe) {
        $exe = Get-ChildItem -Path $Root -Filter "*.exe" -Recurse -File | Select-Object -First 1
    }
    if (-not $exe) {
        throw "No runner EXE found in staged package."
    }
    return $exe
}

$AppDir = Join-Path $InstallRoot "app"
$ConfigDir = Join-Path $InstallRoot "config"
$DataDir = Join-Path $InstallRoot "data"
$LogsDir = Join-Path $InstallRoot "logs"
$RollbackDir = Join-Path $InstallRoot "rollback"
$TempRoot = Join-Path $InstallRoot "tmp"
$Stamp = Get-Date -Format "yyyyMMddHHmmss"
$DownloadZip = Join-Path $TempRoot "runner-$Stamp.zip"
$ExtractDir = Join-Path $TempRoot "extract-$Stamp"
$StageDir = Join-Path $TempRoot "app-stage-$Stamp"
$BackupDir = Join-Path $RollbackDir "app-$Stamp"

New-Directory $InstallRoot
New-Directory $ConfigDir
New-Directory $DataDir
New-Directory $LogsDir
New-Directory $RollbackDir
New-Directory $TempRoot

Write-Host "Downloading approved Soun Runner package from $Repository..."
if ($UseActionsArtifact) {
    $downloadUrl = Get-ActionsArtifactUrl
    Save-RemoteFile -Uri $downloadUrl -OutFile $DownloadZip -UseAuth
}
else {
    $download = Get-ReleaseAssetDownload
    Save-RemoteFile -Uri $download.Uri -OutFile $DownloadZip -UseAuth:([bool]$download.UseAuth)
}

New-Directory $ExtractDir
Expand-Archive -Path $DownloadZip -DestinationPath $ExtractDir -Force

$nestedZip = Get-ChildItem -Path $ExtractDir -Filter "SounAlHosnAssessmentRunner-windows*.zip" -Recurse -File |
    Select-Object -First 1
if ($nestedZip) {
    $innerZip = Join-Path $TempRoot "inner-$Stamp.zip"
    Copy-Item -Path $nestedZip.FullName -Destination $innerZip -Force
    Remove-Item -Path $ExtractDir -Recurse -Force
    New-Directory $ExtractDir
    Expand-Archive -Path $innerZip -DestinationPath $ExtractDir -Force
    Remove-Item -Path $innerZip -Force
}

$stagedExe = Find-RunnerExe -Root $ExtractDir
$packageRoot = $stagedExe.Directory.FullName
Copy-Item -Path $packageRoot -Destination $StageDir -Recurse -Force
$finalStagedExe = Find-RunnerExe -Root $StageDir

Write-Host "Validating staged build..."
& $finalStagedExe.FullName --version | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Staged runner failed version check."
}

$installed = $false
try {
    if (Test-Path $AppDir) {
        Move-Item -Path $AppDir -Destination $BackupDir -Force
    }

    Move-Item -Path $StageDir -Destination $AppDir -Force

    $installedExe = Find-RunnerExe -Root $AppDir
    & $installedExe.FullName --version | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Installed runner failed version check."
    }

    $defaultConfig = Join-Path $ConfigDir "config.yaml"
    $exampleConfig = Join-Path $AppDir "config.example.yaml"
    if (-not (Test-Path $defaultConfig) -and (Test-Path $exampleConfig)) {
        Copy-Item -Path $exampleConfig -Destination $defaultConfig -Force
        Write-Host "Created default config: $defaultConfig"
    }

    $runScriptSource = Join-Path $AppDir "scripts\run_assessment.ps1"
    if (Test-Path $runScriptSource) {
        Copy-Item -Path $runScriptSource -Destination (Join-Path $InstallRoot "run_assessment.ps1") -Force
    }

    $installerSource = Join-Path $AppDir "scripts\install_or_update.ps1"
    if (Test-Path $installerSource) {
        Copy-Item -Path $installerSource -Destination (Join-Path $InstallRoot "install_or_update.ps1") -Force
    }

    $installed = $true
    Write-Host "Install/update complete: $AppDir"
    Write-Host "Preserved config: $ConfigDir"
    Write-Host "Preserved data: $DataDir"
    Write-Host "Preserved logs: $LogsDir"
}
finally {
    if (-not $installed) {
        Write-Host "Update failed. Rolling back application files..."
        if (Test-Path $AppDir) {
            Remove-Item -Path $AppDir -Recurse -Force
        }
        if (Test-Path $BackupDir) {
            Move-Item -Path $BackupDir -Destination $AppDir -Force
            Write-Host "Rollback restored: $AppDir"
        }
    }
    if (Test-Path $ExtractDir) {
        Remove-Item -Path $ExtractDir -Recurse -Force
    }
    if (Test-Path $DownloadZip) {
        Remove-Item -Path $DownloadZip -Force
    }
}
