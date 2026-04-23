from __future__ import annotations

from pathlib import Path

from app.core.preflight import run_preflight
from app.core.secrets import mask_sensitive_mapping, resolve_secret


def test_secret_resolution_prefers_environment_and_masks_nested_values(tmp_path: Path, monkeypatch) -> None:
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("file-secret", encoding="utf-8")
    monkeypatch.setenv("TEST_SECRET_ENV", "env-secret")

    resolved = resolve_secret(
        env_name="TEST_SECRET_ENV",
        file_path=str(secret_file),
        description="Test secret",
    )
    masked = mask_sensitive_mapping(
        {"password": "supersecret", "nested": {"token": "abcd1234", "note": "safe"}}
    )

    assert resolved.present
    assert resolved.source_type == "environment"
    assert resolved.value == "env-secret"
    assert masked["password"] != "supersecret"
    assert masked["nested"]["token"] != "abcd1234"
    assert masked["nested"]["note"] == "safe"


def test_preflight_warns_for_plaintext_and_missing_remote_secret_reference(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "remote_windows:",
                "  enabled: true",
                "  username: \"CORP\\\\operator\"",
                "  password_env: \"SOUN_RUNNER_MISSING_REMOTE_SECRET\"",
                "smtp:",
                "  host: \"smtp.example.local\"",
                "  username: \"mailer\"",
                "  password: \"plaintext-not-allowed\"",
                "  sender: \"runner@example.local\"",
                "  recipient: \"soc@example.local\"",
            ]
        ),
        encoding="utf-8",
    )

    config, report = run_preflight(
        config_path=config_path,
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
    )

    secret_check = next(check for check in report.checks if check.name == "secret_sources")

    assert config is not None
    assert secret_check.status == "warning"
    assert "SMTP password is set inline in config" in secret_check.detail
    assert "Remote Windows password was not provided via approved secret sources" in secret_check.detail
