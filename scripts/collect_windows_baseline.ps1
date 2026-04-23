<#
Soun Al Hosn Assessment Runner - Windows baseline collector.
Read-only only. No persistence, evasion, remediation, exploitation, or credential access.
#>

$ErrorActionPreference = "Continue"

$result = [ordered]@{
    ComputerSystem = Get-CimInstance Win32_ComputerSystem | Select-Object Domain, PartOfDomain, Workgroup, Manufacturer, Model
    OperatingSystem = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
    Network = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway
    Firewall = Get-NetFirewallProfile | Select-Object Name, Enabled
    Defender = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled
    Listeners = Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in 3389,445} | Select-Object LocalAddress, LocalPort, State
    Services = Get-Service | Where-Object {$_.Name -match 'WinDefend|Sense|Veeam|Acronis|Backup|AnyDesk|TeamViewer|ScreenConnect|Splashtop|RustDesk'} | Select-Object Name, DisplayName, Status
}

$result | ConvertTo-Json -Depth 6
