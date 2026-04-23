from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.session import AssessmentIntake, SessionManager
from app.modules.backup_platform_import import BackupPlatformImportModule


def test_backup_platform_import_normalizes_imported_backup_evidence(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.backup_platform_import.enabled = True
    config.backup_platform_import.stale_success_days = 7
    import_path = tmp_path / "backup.json"
    import_path.write_text(
        json.dumps(
            {
                "jobs": [
                    {
                        "asset": "dc1",
                        "status": "failed",
                        "last_success": (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d"),
                        "immutable": False,
                        "offline": False,
                        "restore_test": "never",
                        "criticality": "critical",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    config.backup_platform_import.import_paths = [str(import_path)]
    session = SessionManager(config).create_session(_intake())

    result = BackupPlatformImportModule(session, config).run()
    summary = session.database.get_metadata("backup_platform_import_summary", {})
    inventory = AssetInventory(session, config)

    assert result.status == "complete"
    assert len(result.findings) == 4
    assert all(finding.finding_basis == "imported_configuration_evidence" for finding in result.findings)
    assert summary["job_count"] == 1
    assert summary["restore_test_confirmed_count"] == 0
    assert inventory.find_asset("dc1").criticality == "critical"


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
