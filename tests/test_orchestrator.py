from pathlib import Path

from app.collectors.windows_native import WindowsCommandEvidence, WindowsEvidence
from app.core.inventory import AssetInventory
from app.collectors.windows_remote import RemoteWindowsCollectionResult
from app.core.config import AppConfig
from app.core.session import AssessmentIntake, SessionManager
from app.engine.orchestrator import EstateAssessmentModule
from app.scanners.base import NetworkAsset, NetworkService, ScannerResult


def test_estate_orchestrator_tracks_per_host_status(tmp_path: Path, monkeypatch) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.remote_windows.enabled = True
    config.orchestration.max_workers = 2
    session = SessionManager(config).create_session(_intake())
    raw_xml = session.crypto.write_text(session.evidence_dir / "nmap_scan.xml", "<nmaprun />")

    def fake_scan(self, scope):  # noqa: ANN001
        return ScannerResult(
            scanner_name="nmap",
            status="complete",
            detail="ok",
            assets=[
                NetworkAsset(
                    address="10.0.0.10",
                    hostnames=["host-a"],
                    services=[NetworkService(protocol="tcp", port=3389, state="open")],
                ),
                NetworkAsset(
                    address="10.0.0.11",
                    hostnames=["host-b"],
                    services=[NetworkService(protocol="tcp", port=445, state="open")],
                ),
            ],
            raw_evidence_path=raw_xml,
        )

    def fake_collect(self, *, target: str, asset_id: str):  # noqa: ANN001
        evidence = WindowsEvidence(supported=True, collected_at="2026-01-01T00:00:00+00:00")
        evidence.sections["defender_status"] = WindowsCommandEvidence(
            name="defender_status",
            command="x",
            returncode=0,
            stdout="{}",
            stderr="" if target.endswith(".10") else "Access is denied.",
            parsed_json={},
        )
        evidence.raw_evidence_path = session.crypto.write_text(
            session.evidence_dir / "hosts" / asset_id / "windows_remote_evidence.json",
            "{}",
        )
        return RemoteWindowsCollectionResult(
            target=target,
            status="complete" if target.endswith(".10") else "partial",
            detail="ok" if target.endswith(".10") else "denied",
            evidence=evidence,
            evidence_path=evidence.raw_evidence_path,
        )

    monkeypatch.setattr("app.engine.orchestrator.NmapAdapter.scan", fake_scan)
    monkeypatch.setattr("app.engine.orchestrator.RemoteWindowsCollector.collect", fake_collect)

    result = EstateAssessmentModule(session=session, config=config, package="standard").run()
    coverage = session.database.get_metadata("estate_summary", {}).get("coverage", {})
    asset_statuses = session.database.list_asset_module_statuses()

    assert result.status == "partial"
    assert coverage["total_assets"] == 2
    assert coverage["assessed"] == 1
    assert coverage["partial"] == 1
    assert any(status["module_name"] == "remote_windows_collection" for status in asset_statuses)


def test_estate_orchestrator_uses_imported_assets_for_remote_collection(tmp_path: Path, monkeypatch) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.remote_windows.enabled = True
    config.nmap.enabled = False
    session = SessionManager(config).create_session(_intake())
    inventory = AssetInventory(session, config)
    imported = inventory.record_imported_asset(
        hostname="server-imported",
        ip_address="10.0.0.25",
        source="scanner_import",
    )

    def fake_collect(self, *, target: str, asset_id: str):  # noqa: ANN001
        evidence = WindowsEvidence(supported=True, collected_at="2026-01-01T00:00:00+00:00")
        evidence.sections["defender_status"] = WindowsCommandEvidence(
            name="defender_status",
            command="x",
            returncode=0,
            stdout="{}",
            stderr="",
            parsed_json={},
        )
        evidence.raw_evidence_path = session.crypto.write_text(
            session.evidence_dir / "hosts" / asset_id / "windows_remote_evidence.json",
            "{}",
        )
        return RemoteWindowsCollectionResult(
            target=target,
            status="complete",
            detail="ok",
            evidence=evidence,
            evidence_path=evidence.raw_evidence_path,
        )

    monkeypatch.setattr("app.engine.orchestrator.RemoteWindowsCollector.collect", fake_collect)

    result = EstateAssessmentModule(session=session, config=config, package="standard").run()
    coverage = session.database.get_metadata("estate_summary", {}).get("coverage", {})
    status = session.database.list_asset_module_statuses(imported.asset_id)

    assert result.status == "complete"
    assert coverage["assessed"] == 1
    assert any(item["module_name"] == "remote_windows_collection" and item["status"] == "complete" for item in status)


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="10.0.0.0/24",
        scope_notes="test",
        consent_confirmed=True,
    )
