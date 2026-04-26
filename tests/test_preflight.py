from pathlib import Path

from app.core.auto_context import AutoEnterpriseContext, DetectedInterface
from app.core.preflight import preflight_exit_code, run_preflight


def test_preflight_fails_for_missing_config(tmp_path: Path) -> None:
    config, report = run_preflight(
        config_path=tmp_path / "missing.yaml",
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
    )

    assert config is None
    assert report.overall_status == "failed"
    assert preflight_exit_code(report) == 1


def test_preflight_warns_for_callback_misconfiguration(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "callback:",
                "  enabled: true",
                "  upload_bundle: true",
            ]
        ),
        encoding="utf-8",
    )

    config, report = run_preflight(
        config_path=config_path,
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
    )

    assert config is not None
    assert report.overall_status == "degraded"
    assert any(check.name == "callback" and check.status == "warning" for check in report.checks)


def test_preflight_reports_estate_readiness(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "assessment:",
                "  approved_scopes:",
                "    - 10.0.0.0/24",
                "remote_windows:",
                "  enabled: true",
            ]
        ),
        encoding="utf-8",
    )

    config, report = run_preflight(
        config_path=config_path,
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
    )

    assert config is not None
    estate_check = next(check for check in report.checks if check.name == "estate_readiness")
    assert estate_check.status == "ok"
    assert "10.0.0.0/24" in estate_check.detail


def test_preflight_reports_auto_scope_debug(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "app.core.preflight.detect_enterprise_context",
        lambda _config: AutoEnterpriseContext(
            hostname="runner01",
            fqdn="runner01.corp.example.com",
            operator_name="Operator",
            os_name="Windows",
            domain_joined=True,
            domain_name="corp.example.com",
            dns_suffixes=["corp.example.com"],
            interfaces=[
                DetectedInterface(
                    name="Wi-Fi",
                    ip_address="10.0.169.50",
                    prefix_length=24,
                    subnet="10.0.169.0/24",
                )
            ],
            private_subnets=["10.0.169.0/24"],
            scope_source="auto_detected_local_subnets",
            default_scope="10.0.169.0/24",
            site_label="CORP",
            business_unit="",
            email_domain="corp.example.com",
            ad_domain="corp.example.com",
            adapter_diagnostics=[
                {
                    "name": "Wi-Fi",
                    "ip_address": "10.0.169.50",
                    "prefix_length": 24,
                    "subnet": "10.0.169.0/24",
                    "decision": "selected",
                    "reason": "selected",
                }
            ],
        ),
    )

    config, report = run_preflight(
        config_path=None,
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
    )

    assert config is not None
    check = next(item for item in report.checks if item.name == "auto_scope_detection")
    assert check.status == "ok"
    assert "scope_source=auto_detected_local_subnets" in check.detail
    assert "selected_scope=10.0.169.0/24" in check.detail
