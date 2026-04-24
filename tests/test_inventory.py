from pathlib import Path

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.session import AssessmentIntake, SessionManager
from app.profiling.environment import EnvironmentProfile
from app.scanners.base import NetworkAsset, NetworkService


def test_inventory_records_local_and_discovered_assets(tmp_path: Path) -> None:
    session = SessionManager(
        AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    ).create_session(_intake())
    inventory = AssetInventory(session)

    profile = EnvironmentProfile(
        os_name="Windows",
        os_version="11",
        hostname="workstation01",
        domain_joined=False,
        domain_or_workgroup="WORKGROUP",
        network_interfaces=[
            {
                "interface": "Ethernet0",
                "ipv4": {"IPAddress": "10.0.0.15", "PrefixLength": 24},
                "gateway": {},
            }
        ],
        local_subnets=["10.0.0.0/24"],
        current_user="operator",
        is_admin=False,
        av_indicators=[],
        firewall_status="enabled",
        backup_indicators=[],
        remote_access_indicators=[],
        m365_connector_available=False,
        rdp_enabled=False,
        smb_enabled=False,
        evidence_files=[],
    )
    local_asset = inventory.record_local_profile(profile, evidence_paths=["evidence/profile.json.enc"])
    discovered = inventory.record_discovery(
        NetworkAsset(
            address="10.0.1.10",
            hostnames=["server01"],
            services=[NetworkService(protocol="tcp", port=445, state="open")],
            os_guess="Windows Server 2022",
        )
    )
    inventory.attach_evidence(discovered.asset_id, "evidence/nmap_scan.xml.enc", "network_discovery")
    inventory.mark_status(
        discovered.asset_id,
        assessment_status="partial",
        collector_status="partial",
        error_state="access_denied",
    )

    assets = inventory.list_assets()
    coverage = inventory.coverage_summary()

    assert any(asset.asset_id == local_asset.asset_id and asset.assessment_status == "assessed" for asset in assets)
    assert any(asset.asset_id == discovered.asset_id and asset.collector_status == "partial" for asset in assets)
    assert any(
        asset.asset_id == discovered.asset_id
        and "nmap" in asset.discovery_sources
        and asset.last_successful_evidence_source == "nmap"
        for asset in assets
    )
    assert coverage["total_assets"] == 2
    assert coverage["assessed"] == 1
    assert coverage["partial"] == 1


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="10.0.0.0/24,10.0.1.0/24",
        scope_notes="test",
        consent_confirmed=True,
        scope_labels={
            "10.0.0.0/24": "HQ",
            "10.0.1.0/24": "Branch",
        },
    )
