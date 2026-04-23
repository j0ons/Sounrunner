from pathlib import Path

from app.core.config import AppConfig
from app.core.session import AssessmentIntake, SessionManager
from app.scanners.greenbone_api import GreenboneApiClient
from app.scanners.nessus_api import NessusApiClient


NESSUS_XML = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Example">
    <ReportHost name="host1">
      <HostProperties>
        <tag name="host-ip">10.0.0.10</tag>
      </HostProperties>
      <ReportItem port="445" protocol="tcp" severity="3" pluginID="1234" pluginName="SMB Signing Disabled">
        <description>SMB signing is disabled.</description>
        <solution>Enable SMB signing.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

GREENBONE_XML = """<get_reports_response status="200" status_text="OK">
  <report id="r1">
    <results>
      <result id="res1">
        <host>10.0.0.11</host>
        <port>3389/tcp</port>
        <name>RDP Service Exposed</name>
        <threat>High</threat>
        <severity>8.5</severity>
        <description>RDP is accessible.</description>
        <solution>Restrict exposure.</solution>
      </result>
    </results>
  </report>
</get_reports_response>
"""


def test_nessus_api_fetch_uses_parser(tmp_path: Path, monkeypatch) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.scanner_integrations.nessus_api.enabled = True
    config.scanner_integrations.nessus_api.base_url = "https://cloud.tenable.example"
    config.scanner_integrations.nessus_api.scan_id = "42"
    monkeypatch.setenv(config.scanner_integrations.nessus_api.access_key_env, "key")
    monkeypatch.setenv(config.scanner_integrations.nessus_api.secret_key_env, "secret")
    session = SessionManager(config).create_session(_intake())
    client = NessusApiClient(session, config.scanner_integrations.nessus_api)
    monkeypatch.setattr(NessusApiClient, "_request_export", lambda self: "file-1")
    monkeypatch.setattr(NessusApiClient, "_wait_for_export", lambda self, file_id: None)
    monkeypatch.setattr(
        NessusApiClient,
        "_download_export",
        lambda self, file_id: NESSUS_XML.encode("utf-8"),
    )

    result = client.fetch_scan_export()

    assert result.status == "complete"
    assert result.raw_evidence_path and result.raw_evidence_path.exists()
    assert result.findings


def test_greenbone_api_fetch_uses_parser(tmp_path: Path, monkeypatch) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.scanner_integrations.greenbone_api.enabled = True
    config.scanner_integrations.greenbone_api.host = "greenbone.example"
    config.scanner_integrations.greenbone_api.username = "operator"
    monkeypatch.setenv(config.scanner_integrations.greenbone_api.password_env, "secret")
    session = SessionManager(config).create_session(_intake())
    client = GreenboneApiClient(session, config.scanner_integrations.greenbone_api)
    monkeypatch.setattr(GreenboneApiClient, "_download_report_xml", lambda self, password: GREENBONE_XML)

    result = client.fetch_report()

    assert result.status == "complete"
    assert result.raw_evidence_path and result.raw_evidence_path.exists()
    assert result.findings


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="local-host-only",
        scope_notes="test",
        consent_confirmed=True,
    )
