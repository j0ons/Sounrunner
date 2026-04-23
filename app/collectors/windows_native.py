"""Windows-native read-only evidence collection."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.collectors.windows import is_windows, powershell_available, run_powershell
from app.core.evidence import utc_now
from app.core.session import AssessmentSession


@dataclass(slots=True)
class WindowsCommandEvidence:
    """Raw and parsed output for one Windows-native evidence command."""

    name: str
    command: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    parsed_json: dict[str, Any] | list[Any] | None = None

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass(slots=True)
class WindowsEvidence:
    """Session-level Windows evidence bundle."""

    supported: bool
    collected_at: str
    raw_evidence_path: Path | None = None
    sections: dict[str, WindowsCommandEvidence] = field(default_factory=dict)

    def section(self, name: str) -> WindowsCommandEvidence | None:
        return self.sections.get(name)

    def section_json(self, name: str) -> dict[str, Any]:
        section = self.section(name)
        if not section or section.parsed_json is None:
            return {}
        if isinstance(section.parsed_json, dict):
            return section.parsed_json
        return {"items": section.parsed_json}

    def section_items(self, name: str) -> list[Any]:
        payload = self.section_json(name)
        if "items" in payload and isinstance(payload["items"], list):
            return payload["items"]
        if payload:
            return [payload]
        return []

    def section_text(self, name: str) -> str:
        section = self.section(name)
        return section.stdout if section else ""

    def succeeded(self, name: str) -> bool:
        section = self.section(name)
        return bool(section and section.succeeded)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["raw_evidence_path"] = str(self.raw_evidence_path) if self.raw_evidence_path else ""
        return payload


class WindowsNativeCollector:
    """Collect direct Windows evidence without modifying host state."""

    name = "windows_native_evidence"

    COMMANDS: dict[str, str] = {
        "defender_status": (
            "if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { "
            "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,"
            "RealTimeProtectionEnabled,AntispywareEnabled,IoavProtectionEnabled,"
            "NISEnabled,AntivirusSignatureAge,AntivirusSignatureLastUpdated,"
            "FullScanAge,QuickScanAge | ConvertTo-Json -Depth 6 "
            "} else { @{Unavailable='Get-MpComputerStatus not available'} | ConvertTo-Json }"
        ),
        "defender_preferences": (
            "if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) { "
            "Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableIOAVProtection,"
            "DisableBehaviorMonitoring,DisableBlockAtFirstSeen,PUAProtection,"
            "MAPSReporting,SubmitSamplesConsent | ConvertTo-Json -Depth 6 "
            "} else { @{Unavailable='Get-MpPreference not available'} | ConvertTo-Json }"
        ),
        "firewall_profiles": (
            "if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) { "
            "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,"
            "DefaultOutboundAction,NotifyOnListen,LogAllowed,LogBlocked,LogFileName "
            "| ConvertTo-Json -Depth 6 "
            "} else { @{Unavailable='Get-NetFirewallProfile not available'} | ConvertTo-Json }"
        ),
        "local_administrators": (
            "try { "
            "Get-LocalGroupMember -Group Administrators | "
            "Select-Object Name,ObjectClass,PrincipalSource,SID | ConvertTo-Json -Depth 6 "
            "} catch { @{Error=$_.Exception.Message; Fallback=(net localgroup administrators | Out-String)} "
            "| ConvertTo-Json -Depth 6 }"
        ),
        "password_policy": "net accounts",
        "current_user_groups": "whoami /groups",
        "rdp_status": (
            "try { "
            "$rdp = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name fDenyTSConnections -ErrorAction SilentlyContinue; "
            "$svc = Get-Service TermService -ErrorAction SilentlyContinue; "
            "$listen = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue; "
            "$rules = Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | "
            "Select-Object DisplayName,Enabled,Direction,Action,Profile; "
            "[pscustomobject]@{fDenyTSConnections=$rdp.fDenyTSConnections;"
            "ServiceStatus=$(if ($svc) {$svc.Status.ToString()} else {'Unavailable'}); "
            "ListenerCount=@($listen).Count; FirewallRules=$rules} | ConvertTo-Json -Depth 8 "
            "} catch { @{Error=$_.Exception.Message} | ConvertTo-Json -Depth 6 }"
        ),
        "smb_status": (
            "try { "
            "$cfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue; "
            "$svc = Get-Service LanmanServer -ErrorAction SilentlyContinue; "
            "$listen = Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue; "
            "[pscustomobject]@{EnableSMB1Protocol=$cfg.EnableSMB1Protocol;"
            "EnableSMB2Protocol=$cfg.EnableSMB2Protocol;"
            "RequireSecuritySignature=$cfg.RequireSecuritySignature;"
            "EncryptData=$cfg.EncryptData;ServiceStatus=$(if ($svc) {$svc.Status.ToString()} else {'Unavailable'});"
            "ListenerCount=@($listen).Count} | ConvertTo-Json -Depth 6 "
            "} catch { @{Error=$_.Exception.Message} | ConvertTo-Json -Depth 6 }"
        ),
        "bitlocker_status": (
            "if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { "
            "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,"
            "EncryptionPercentage,EncryptionMethod | ConvertTo-Json -Depth 6 "
            "} else { @{Unavailable='Get-BitLockerVolume not available'} | ConvertTo-Json }"
        ),
        "hotfixes": (
            "try { "
            "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 "
            "HotFixID,Description,InstalledBy,InstalledOn | ConvertTo-Json -Depth 6 "
            "} catch { @{Error=$_.Exception.Message} | ConvertTo-Json -Depth 6 }"
        ),
        "backup_indicators": (
            "$services = Get-Service | Where-Object {$_.Name -match "
            "'Veeam|Acronis|BackupExec|Macrium|Datto|Carbonite|wbengine|SQLWriter|Backup'} "
            "| Select-Object Name,DisplayName,Status; "
            "$apps = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
            "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            "-ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -match "
            "'Veeam|Acronis|Backup Exec|Macrium|Datto|Carbonite|Windows Server Backup'} "
            "| Select-Object DisplayName,DisplayVersion,Publisher; "
            "[pscustomobject]@{Services=$services; InstalledApps=$apps} | ConvertTo-Json -Depth 8"
        ),
        "logging_visibility": (
            "try { "
            "$eventLog = Get-Service EventLog -ErrorAction SilentlyContinue; "
            "$channels = wevtutil el 2>$null | Select-Object -First 30; "
            "[pscustomobject]@{EventLogStatus=$(if ($eventLog) {$eventLog.Status.ToString()} else {'Unavailable'});"
            "ChannelSample=$channels;ChannelSampleCount=@($channels).Count} | ConvertTo-Json -Depth 6 "
            "} catch { @{Error=$_.Exception.Message} | ConvertTo-Json -Depth 6 }"
        ),
        "remote_access_software": (
            "$serviceMatches = Get-Service | Where-Object {$_.Name -match "
            "'AnyDesk|TeamViewer|ScreenConnect|Splashtop|RustDesk|LogMeIn|GoToAssist|ConnectWise'} "
            "| Select-Object Name,DisplayName,Status; "
            "$apps = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
            "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            "-ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -match "
            "'AnyDesk|TeamViewer|ScreenConnect|Splashtop|RustDesk|LogMeIn|GoToAssist|ConnectWise'} "
            "| Select-Object DisplayName,DisplayVersion,Publisher; "
            "[pscustomobject]@{Services=$serviceMatches; InstalledApps=$apps} | ConvertTo-Json -Depth 8"
        ),
    }

    def __init__(self, session: AssessmentSession) -> None:
        self.session = session
        self.evidence = WindowsEvidence(
            supported=is_windows() and powershell_available(),
            collected_at=utc_now(),
        )

    def collect(self) -> WindowsEvidence:
        if not self.evidence.supported:
            self.evidence.raw_evidence_path = self.session.crypto.write_text(
                self.session.evidence_dir / "windows_native_evidence.json",
                json.dumps(self.evidence.to_dict(), indent=2, sort_keys=True),
            )
            return self.evidence

        for name, command in self.COMMANDS.items():
            result = run_powershell(command, timeout_seconds=45)
            self.evidence.sections[name] = WindowsCommandEvidence(
                name=name,
                command=command,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                timed_out=result.timed_out,
                parsed_json=_try_json(result.stdout),
            )

        self.evidence.raw_evidence_path = self.session.crypto.write_text(
            self.session.evidence_dir / "windows_native_evidence.json",
            json.dumps(self.evidence.to_dict(), indent=2, sort_keys=True),
        )
        return self.evidence


def parse_password_policy(output: str) -> dict[str, str]:
    """Parse English `net accounts` output into normalized keys.

    Non-English Windows output will not parse reliably. In that case the raw
    evidence is still preserved and modules should avoid making claims.
    """

    parsed: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = " ".join(key.strip().lower().split())
        parsed[normalized_key] = value.strip()
    return parsed


def evidence_items(payload: object) -> list[dict[str, Any]]:
    """Return dict items from PowerShell JSON that may be object or array."""

    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return [item for item in payload["items"] if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def _try_json(raw: str) -> dict[str, Any] | list[Any] | None:
    if not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, (dict, list)):
        return parsed
    return None
