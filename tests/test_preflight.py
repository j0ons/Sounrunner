from pathlib import Path

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
