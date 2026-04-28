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
    config.remote_windows.require_winrm_port_observed = False
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
    inventory_assets = session.database.get_metadata("inventory_assets", [])
    assert any(item["remoting_eligible"] for item in inventory_assets)


def test_estate_orchestrator_uses_imported_assets_for_remote_collection(tmp_path: Path, monkeypatch) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.remote_windows.enabled = True
    config.remote_windows.require_winrm_port_observed = False
    config.nmap.enabled = False
    session = SessionManager(config).create_session(_intake())
    inventory = AssetInventory(session, config)
    imported = inventory.record_imported_asset(
        hostname="server-imported",
        ip_address="10.0.0.25",
        source="scanner_import",
    )
    imported.os_family = "Windows"
    imported.os_guess = "Microsoft Windows Server"
    inventory.upsert(imported)

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
    refreshed = inventory.find_asset(imported.asset_id)
    assert refreshed is not None
    assert refreshed.last_successful_evidence_source == "remote_windows_collection"
    assert refreshed.remoting_eligible is True


def test_estate_orchestrator_auto_attempts_current_user_winrm_when_domain_context_exists(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.remote_windows.enabled = False
    config.remote_windows.require_winrm_port_observed = True
    config.active_directory.domain = "corp.example.local"
    session = SessionManager(config).create_session(_intake())
    session.database.set_metadata(
        "auto_context",
        {
            "domain_joined": True,
            "domain_name": "corp.example.local",
            "operator_name": "CORP\\operator",
        },
    )
    raw_xml = session.crypto.write_text(session.evidence_dir / "nmap_scan.xml", "<nmaprun />")

    def fake_scan(self, scope):  # noqa: ANN001
        return ScannerResult(
            scanner_name="nmap",
            status="complete",
            detail="ok",
            assets=[
                NetworkAsset(
                    address="10.0.0.20",
                    hostnames=["winrm-host"],
                    services=[NetworkService(protocol="tcp", port=5985, state="open", service_name="wsman")],
                )
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

    monkeypatch.setattr("app.engine.remote_strategy.is_windows", lambda: True)
    monkeypatch.setattr("app.engine.remote_strategy.powershell_available", lambda: True)
    monkeypatch.setattr("app.engine.orchestrator.NmapAdapter.scan", fake_scan)
    monkeypatch.setattr("app.engine.orchestrator.RemoteWindowsCollector.collect", fake_collect)

    result = EstateAssessmentModule(session=session, config=config, package="standard").run()
    strategy = session.database.get_metadata("remote_collection_strategy", {})
    summary = session.database.get_metadata("remote_collection_summary", {})

    assert result.status == "complete"
    assert strategy["mode"] == "current_user_integrated_auth"
    assert strategy["current_user_context"] is True
    assert "password" not in str(strategy).lower()
    assert summary["collection_attempted"] == 1
    assert summary["collection_successful"] == 1


def test_estate_orchestrator_skips_candidates_without_observed_winrm_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.active_directory.domain = "corp.example.local"
    session = SessionManager(config).create_session(_intake())
    session.database.set_metadata("auto_context", {"domain_joined": True, "domain_name": "corp.example.local"})
    raw_xml = session.crypto.write_text(session.evidence_dir / "nmap_scan.xml", "<nmaprun />")

    def fake_scan(self, scope):  # noqa: ANN001
        return ScannerResult(
            scanner_name="nmap",
            status="complete",
            detail="ok",
            assets=[
                NetworkAsset(
                    address="10.0.0.30",
                    hostnames=["rdp-only"],
                    services=[NetworkService(protocol="tcp", port=3389, state="open", service_name="ms-wbt-server")],
                )
            ],
            raw_evidence_path=raw_xml,
        )

    monkeypatch.setattr("app.engine.remote_strategy.is_windows", lambda: True)
    monkeypatch.setattr("app.engine.remote_strategy.powershell_available", lambda: True)
    monkeypatch.setattr("app.engine.orchestrator.NmapAdapter.scan", fake_scan)

    result = EstateAssessmentModule(session=session, config=config, package="standard").run()
    statuses = session.database.list_asset_module_statuses()
    summary = session.database.get_metadata("remote_collection_summary", {})

    assert result.status == "partial"
    assert summary["probable_windows"] == 1
    assert summary["windows_candidates"] == 1
    assert summary["remote_eligible"] == 0
    assert summary["not_eligible_no_winrm"] == 1
    assert summary["collection_attempted"] == 0
    assert any("no_winrm_service_detected" in item["detail"] for item in statuses)


def test_estate_orchestrator_fingerprints_winrm_host_as_remote_eligible(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.active_directory.domain = "corp.example.local"
    session = SessionManager(config).create_session(_intake())
    session.database.set_metadata("auto_context", {"domain_joined": True, "domain_name": "corp.example.local"})
    raw_xml = session.crypto.write_text(session.evidence_dir / "nmap_scan.xml", "<nmaprun />")

    def fake_scan(self, scope):  # noqa: ANN001
        return ScannerResult(
            scanner_name="nmap",
            status="complete",
            detail="ok",
            assets=[
                NetworkAsset(
                    address="10.0.0.40",
                    hostnames=["winrm-host"],
                    services=[NetworkService(protocol="tcp", port=5985, state="open", service_name="wsman")],
                )
            ],
            raw_evidence_path=raw_xml,
        )

    def fake_collect(self, *, target: str, asset_id: str):  # noqa: ANN001
        evidence = WindowsEvidence(supported=True, collected_at="2026-01-01T00:00:00+00:00")
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

    monkeypatch.setattr("app.engine.remote_strategy.is_windows", lambda: True)
    monkeypatch.setattr("app.engine.remote_strategy.powershell_available", lambda: True)
    monkeypatch.setattr("app.engine.orchestrator.NmapAdapter.scan", fake_scan)
    monkeypatch.setattr("app.engine.orchestrator.RemoteWindowsCollector.collect", fake_collect)

    EstateAssessmentModule(session=session, config=config, package="standard").run()
    summary = session.database.get_metadata("remote_collection_summary", {})

    assert summary["probable_windows"] == 1
    assert summary["remote_eligible"] == 1
    assert summary["collection_attempted"] == 1


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
