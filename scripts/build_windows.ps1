param(
    [string]$Name = "SounAlHosnAssessmentRunner"
)

$ErrorActionPreference = "Stop"

Write-Host "Building Windows EXE with PyInstaller..."
python -m PyInstaller --name $Name --onefile --console main.py
Write-Host "Build complete: .\dist\$Name.exe"
