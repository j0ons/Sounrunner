from app.modules.endpoint import EndpointModule
from app.profiling.environment import EnvironmentProfile


def test_endpoint_module_does_not_emit_windows_findings_on_non_windows() -> None:
    profile = EnvironmentProfile(
        os_name="Darwin",
        os_version="test",
        hostname="host",
        domain_joined=False,
        domain_or_workgroup="unsupported-non-windows",
        network_interfaces=[],
        local_subnets=[],
        current_user="operator",
        is_admin=False,
        av_indicators=[],
        firewall_status="unknown",
        backup_indicators=[],
        remote_access_indicators=[],
        m365_connector_available=False,
        rdp_enabled=False,
        smb_enabled=False,
    )

    result = EndpointModule(session=object(), profile=profile).run()

    assert result.status == "partial"
    assert result.findings == []
