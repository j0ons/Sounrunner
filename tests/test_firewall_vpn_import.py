from __future__ import annotations

import json
from pathlib import Path

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.session import AssessmentIntake, SessionManager
from app.modules.firewall_vpn_import import FirewallVpnImportModule


def test_firewall_vpn_import_normalizes_imported_network_control_evidence(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.firewall_vpn_import.enabled = True
    import_path = tmp_path / "firewall.json"
    import_path.write_text(
        json.dumps(
            {
                "management_exposures": [
                    {
                        "asset": "fw-hq",
                        "service": "https",
                        "internet_exposed": True,
                        "admin_interface": True,
                        "site": "HQ",
                    }
                ],
                "vpn_endpoints": [
                    {
                        "asset": "vpn-hq",
                        "internet_exposed": True,
                        "site": "HQ",
                    }
                ],
                "policies": [
                    {
                        "asset": "fw-hq",
                        "policy_name": "Allow-Any-RDP",
                        "source": "any",
                        "destination": "any",
                        "service": "RDP",
                        "site": "HQ",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    config.firewall_vpn_import.import_paths = [str(import_path)]
    session = SessionManager(config).create_session(_intake())

    result = FirewallVpnImportModule(session, config).run()
    summary = session.database.get_metadata("firewall_vpn_import_summary", {})
    inventory = AssetInventory(session, config)

    assert result.status == "complete"
    assert len(result.findings) == 3
    assert all(finding.finding_basis == "imported_configuration_evidence" for finding in result.findings)
    assert summary["parsed_files"] == 1
    assert inventory.find_asset("fw-hq").asset_role == "network_device"


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="10.0.0.0/24",
        scope_notes="authorized",
        consent_confirmed=True,
    )
