from pathlib import Path

import pytest

from app.core.config import AppConfig


def test_config_enforces_read_only(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("read_only: false\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Read-only"):
        AppConfig.load(config_file)


def test_default_config_loads() -> None:
    config = AppConfig.load()
    assert config.read_only is True
    assert config.report_company_name


def test_cli_path_overrides_win_over_config(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "workspace_root: old-data\nlog_root: old-logs\nread_only: true\n",
        encoding="utf-8",
    )

    config = AppConfig.load(
        config_file,
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
    )

    assert config.workspace_root == tmp_path / "data"
    assert config.log_root == tmp_path / "logs"
