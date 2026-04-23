from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.collectors.ad_directory import ActiveDirectoryEvidence
from app.collectors.windows_native import WindowsCommandEvidence
from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.session import AssessmentIntake, SessionManager
from app.modules.active_directory import ActiveDirectoryModule


def test_active_directory_module_normalizes_directory_findings_and_assets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.active_directory.enabled = True
    session = SessionManager(config).create_session(_intake())
    raw_path = session.crypto.write_text(session.evidence_dir / "ad_raw.json", "{}")
    stale_date = (datetime.now(timezone.utc) - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S")

    evidence = ActiveDirectoryEvidence(
        supported=True,
        collected_at="2026-01-01T00:00:00+00:00",
        raw_evidence_path=raw_path,
        sections={
            "module_check": _section(stdout="available"),
            "domain_info": _section(
                parsed_json={"DNSRoot": "corp.example.local", "DomainMode": "Windows2016Domain"}
            ),
            "domain_controllers": _section(
                parsed_json=[
                    {
                        "HostName": "dc1.corp.example.local",
                        "Site": "HQ",
                        "IPv4Address": "10.0.0.10",
                        "OperatingSystem": "Windows Server 2022",
                    }
                ]
            ),
            "computers": _section(
                parsed_json=[
                    {
                        "Name": "DC1",
                        "DNSHostName": "dc1.corp.example.local",
                        "OperatingSystem": "Windows Server 2022",
                        "Enabled": True,
                        "DistinguishedName": "CN=DC1,OU=Domain Controllers,DC=corp,DC=example,DC=local",
                        "Site": "HQ",
                    },
                    {
                        "Name": "APP-SRV-01",
                        "DNSHostName": "app-srv-01.corp.example.local",
                        "OperatingSystem": "Windows Server 2019",
                        "Enabled": True,
                        "DistinguishedName": "CN=APP-SRV-01,OU=Servers,OU=IT,DC=corp,DC=example,DC=local",
                        "Site": "HQ",
                    },
                    {
                        "Name": "WS-01",
                        "DNSHostName": "ws-01.corp.example.local",
                        "OperatingSystem": "Windows 11 Pro",
                        "Enabled": True,
                        "DistinguishedName": "CN=WS-01,OU=Workstations,OU=Finance,DC=corp,DC=example,DC=local",
                        "Site": "Branch-A",
                    },
                ]
            ),
            "users": _section(
                parsed_json=[
                    {"SamAccountName": "stale.user", "Enabled": True, "LastLogonDate": stale_date},
                    {"SamAccountName": "active.user", "Enabled": True, "LastLogonDate": "2026-01-01T00:00:00"},
                ]
            ),
            "privileged_groups": _section(
                parsed_json=[
                    {"Group": "Domain Admins", "MemberCount": 6},
                    {"Group": "Enterprise Admins", "MemberCount": 3},
                ]
            ),
            "password_policy": _section(
                parsed_json={"MinPasswordLength": 8, "LockoutThreshold": 0}
            ),
            "organizational_units": _section(parsed_json=[]),
        },
    )

    monkeypatch.setattr(
        "app.modules.active_directory.ActiveDirectoryCollector.collect",
        lambda self: evidence,
    )

    result = ActiveDirectoryModule(session, config).run()
    inventory = AssetInventory(session, config)
    assets = inventory.list_assets()

    assert result.status == "complete"
    assert any(finding.finding_id == "STANDARD-AD-001" for finding in result.findings)
    assert any(finding.finding_id == "STANDARD-AD-002" for finding in result.findings)
    assert any(finding.finding_id == "STANDARD-AD-003" for finding in result.findings)
    assert all(finding.finding_basis == "directory_evidence" for finding in result.findings)
    assert any(asset.asset_role == "domain_controller" for asset in assets)
    assert any(asset.asset_role == "server" for asset in assets)
    assert any(asset.asset_role == "workstation" for asset in assets)
    assert any(asset.business_unit == "IT" for asset in assets)


def _section(
    *,
    stdout: str = "{}",
    stderr: str = "",
    parsed_json: object | None = None,
) -> WindowsCommandEvidence:
    return WindowsCommandEvidence(
        name="test",
        command="test",
        returncode=0,
        stdout=stdout,
        stderr=stderr,
        parsed_json=parsed_json,  # type: ignore[arg-type]
    )


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="10.0.0.0/24",
        scope_notes="authorized",
        consent_confirmed=True,
        ad_domain="corp.example.local",
        business_unit="IT",
    )
