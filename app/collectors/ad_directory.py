"""Read-only Active Directory evidence collection."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.collectors.windows import is_windows, powershell_available, run_powershell
from app.collectors.windows_native import WindowsCommandEvidence, _try_json
from app.core.config import ActiveDirectoryConfig
from app.core.evidence import utc_now
from app.core.session import AssessmentSession


@dataclass(slots=True)
class ActiveDirectoryEvidence:
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

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["raw_evidence_path"] = str(self.raw_evidence_path) if self.raw_evidence_path else ""
        return payload


class ActiveDirectoryCollector:
    """Collect directory evidence through read-only PowerShell AD queries."""

    name = "active_directory_evidence"

    def __init__(
        self,
        session: AssessmentSession,
        config: ActiveDirectoryConfig,
    ) -> None:
        self.session = session
        self.config = config
        self.evidence = ActiveDirectoryEvidence(
            supported=is_windows() and powershell_available() and config.enabled,
            collected_at=utc_now(),
        )

    def collect(self) -> ActiveDirectoryEvidence:
        evidence_path = self.session.evidence_dir / "active_directory_evidence.json"
        if not self.config.enabled:
            self.evidence.raw_evidence_path = self.session.crypto.write_text(
                evidence_path,
                json.dumps(self.evidence.to_dict(), indent=2, sort_keys=True),
            )
            return self.evidence

        if not is_windows() or not powershell_available():
            self.evidence.raw_evidence_path = self.session.crypto.write_text(
                evidence_path,
                json.dumps(self.evidence.to_dict(), indent=2, sort_keys=True),
            )
            return self.evidence

        module_check = run_powershell(
            "if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {'available'} else {'missing'}",
            timeout_seconds=20,
        )
        self.evidence.sections["module_check"] = WindowsCommandEvidence(
            name="module_check",
            command="Get-ADDomain availability check",
            returncode=module_check.returncode,
            stdout=module_check.stdout,
            stderr=module_check.stderr,
            timed_out=module_check.timed_out,
            parsed_json=None,
        )
        if module_check.returncode != 0 or module_check.stdout.strip().lower() != "available":
            self.evidence.supported = False
            self.evidence.raw_evidence_path = self.session.crypto.write_text(
                evidence_path,
                json.dumps(self.evidence.to_dict(), indent=2, sort_keys=True),
            )
            return self.evidence

        for name, command in self._commands().items():
            result = run_powershell(command, timeout_seconds=self.config.query_timeout_seconds)
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
            evidence_path,
            json.dumps(self.evidence.to_dict(), indent=2, sort_keys=True),
        )
        return self.evidence

    def _commands(self) -> dict[str, str]:
        privileged_groups = ", ".join(f"'{name}'" for name in self.config.privileged_groups)
        return {
            "domain_info": (
                "Get-ADDomain | Select-Object DNSRoot,NetBIOSName,DomainMode,PDCEmulator,"
                "RIDMaster,InfrastructureMaster,DistinguishedName | ConvertTo-Json -Depth 6"
            ),
            "domain_controllers": (
                "Get-ADDomainController -Filter * | "
                "Select-Object HostName,Forest,Site,IsGlobalCatalog,IPv4Address,OperatingSystem "
                "| ConvertTo-Json -Depth 6"
            ),
            "computers": (
                f"Get-ADComputer -Filter * -Properties DNSHostName,OperatingSystem,Enabled,LastLogonDate,"
                f"DistinguishedName | Select-Object -First {self.config.computer_limit} "
                "Name,DNSHostName,OperatingSystem,Enabled,LastLogonDate,DistinguishedName "
                "| ConvertTo-Json -Depth 6"
            ),
            "users": (
                f"Get-ADUser -Filter * -Properties Enabled,LastLogonDate,PasswordLastSet,AdminCount,"
                f"DistinguishedName | Select-Object -First {self.config.user_limit} "
                "SamAccountName,Enabled,LastLogonDate,PasswordLastSet,AdminCount,DistinguishedName "
                "| ConvertTo-Json -Depth 6"
            ),
            "privileged_groups": (
                f"$groups = @({privileged_groups}); "
                "$output = foreach ($group in $groups) { "
                "try { "
                "$members = Get-ADGroupMember -Identity $group -ErrorAction Stop | "
                "Select-Object Name,ObjectClass,SamAccountName,DistinguishedName; "
                "[pscustomobject]@{Group=$group; MemberCount=@($members).Count; Members=$members} "
                "} catch { [pscustomobject]@{Group=$group; Error=$_.Exception.Message; MemberCount=0; Members=@()} } "
                "}; $output | ConvertTo-Json -Depth 8"
            ),
            "password_policy": (
                "Get-ADDefaultDomainPasswordPolicy | "
                "Select-Object ComplexityEnabled,LockoutThreshold,MinPasswordLength,PasswordHistoryCount,"
                "MaxPasswordAge,MinPasswordAge,LockoutDuration,LockoutObservationWindow "
                "| ConvertTo-Json -Depth 6"
            ),
            "organizational_units": (
                "Get-ADOrganizationalUnit -Filter * | Select-Object -First 200 Name,DistinguishedName "
                "| ConvertTo-Json -Depth 6"
            ),
        }
