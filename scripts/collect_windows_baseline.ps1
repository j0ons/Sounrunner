<#
Soun Al Hosn Assessment Runner - Windows baseline collector.
Read-only only. No persistence, evasion, remediation, exploitation, or credential access.
#>

$ErrorActionPreference = "Continue"

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

$result = [ordered]@{
    ComputerSystem = Get-CimInstance Win32_ComputerSystem | Select-Object Domain, PartOfDomain, Workgroup, Manufacturer, Model
    OperatingSystem = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
    Network = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway
    Firewall = Get-NetFirewallProfile | Select-Object Name, Enabled
    Defender = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, AntivirusSignatureLastUpdated
    DefenderPreferences = Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableIOAVProtection, DisableBehaviorMonitoring, DisableBlockAtFirstSeen, PUAProtection
    LocalAdministrators = Get-LocalGroupMember -Group Administrators | Select-Object Name, ObjectClass, PrincipalSource, SID
    PasswordPolicy = net accounts
    Rdp = [ordered]@{
        TerminalServer = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue
        Service = Get-Service TermService -ErrorAction SilentlyContinue | Select-Object Name, Status
        Listener = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, State
    }
    Smb = [ordered]@{
        Configuration = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EncryptData
        Service = Get-Service LanmanServer -ErrorAction SilentlyContinue | Select-Object Name, Status
        Listener = Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, State
    }
    BitLocker = Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod
    HotFixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID, Description, InstalledBy, InstalledOn
    Listeners = Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in 3389,445} | Select-Object LocalAddress, LocalPort, State
    Services = Get-Service | Where-Object {$_.Name -match 'WinDefend|Sense|Veeam|Acronis|Backup|AnyDesk|TeamViewer|ScreenConnect|Splashtop|RustDesk'} | Select-Object Name, DisplayName, Status
}

$result | ConvertTo-Json -Depth 6
