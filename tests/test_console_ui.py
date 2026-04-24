from __future__ import annotations

from app.core.config import AppConfig
from app.core.input_normalization import normalize_prompt_value
from app.core.session import AssessmentIntake
from app.ui.console import ConsoleUi
from main import _apply_config_defaults


def _set_inputs(monkeypatch, responses: list[object]) -> None:
    iterator = iter(responses)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(iterator))


def test_normalize_prompt_value_handles_none() -> None:
    assert normalize_prompt_value(None) == ""
    assert normalize_prompt_value("  basic  ") == "basic"


def test_collect_intake_reprompts_for_empty_scope(monkeypatch, capsys) -> None:
    ui = ConsoleUi(app_version="test")
    ui.console = None
    _set_inputs(
        monkeypatch,
        [
            "Client",
            "HQ",
            "Operator",
            "basic",
            "",
            "10.0.0.0/24",
            "",
            "",
            "",
            "",
            "",
            "",
            "n",
            "y",
        ],
    )

    intake = ui.collect_intake()

    assert intake.authorized_scope == "10.0.0.0/24"
    assert "Authorized scope/subnet cannot be blank." in capsys.readouterr().out


def test_collect_intake_reprompts_for_invalid_allowlist_entry(monkeypatch, capsys) -> None:
    ui = ConsoleUi(app_version="test")
    ui.console = None
    _set_inputs(
        monkeypatch,
        [
            "Client",
            "HQ",
            "Operator",
            "basic",
            "local-host-only",
            "CIDR",
            "server01,10.0.0.10",
            "",
            "",
            "",
            "",
            "",
            "n",
            "y",
        ],
    )

    intake = ui.collect_intake()

    assert intake.host_allowlist == ["server01", "10.0.0.10"]
    assert (
        "Invalid host entry 'CIDR'. Expected IP address, hostname, or FQDN. "
        "Put CIDR ranges in Authorized scope/subnet."
    ) in capsys.readouterr().out


def test_collect_intake_blank_optional_fields_are_normalized(monkeypatch) -> None:
    ui = ConsoleUi(app_version="test")
    ui.console = None
    _set_inputs(
        monkeypatch,
        [
            "Client",
            "HQ",
            "Operator",
            "basic",
            "local-host-only",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "yes",
        ],
    )

    intake = ui.collect_intake()

    assert intake.host_allowlist == []
    assert intake.host_denylist == []
    assert intake.ad_domain is None
    assert intake.domain is None
    assert intake.business_unit == ""
    assert intake.scope_notes == "No additional notes."
    assert intake.m365_connector is False


def test_collect_intake_interactive_basic_run_input_normalization(monkeypatch) -> None:
    ui = ConsoleUi(app_version="test")
    ui.console = None
    _set_inputs(
        monkeypatch,
        [
            " Client ",
            " HQ ",
            " Operator ",
            None,
            " local-host-only ",
            None,
            None,
            " corp.local ",
            " Finance ",
            None,
            " example.com ",
            None,
            "y",
        ],
    )

    intake = ui.collect_intake()

    assert intake.client_name == "Client"
    assert intake.site == "HQ"
    assert intake.operator_name == "Operator"
    assert intake.package == "basic"
    assert intake.authorized_scope == "local-host-only"
    assert intake.ad_domain == "corp.local"
    assert intake.business_unit == "Finance"
    assert intake.domain == "example.com"
    assert intake.m365_connector is False
    assert intake.consent_confirmed is True


def test_confirm_reprompts_invalid_yes_no(monkeypatch, capsys) -> None:
    ui = ConsoleUi(app_version="test")
    ui.console = None
    _set_inputs(monkeypatch, ["maybe", "y"])

    assert ui._confirm("Confirm?", default=False) is True
    assert "Confirm? expects yes or no." in capsys.readouterr().out


def test_apply_config_defaults_handles_none_scope() -> None:
    config = AppConfig()
    config.assessment.approved_scope = "local-host-only"
    intake = AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="basic",
        authorized_scope=None,  # type: ignore[arg-type]
        scope_notes="notes",
        consent_confirmed=True,
        domain=None,
        m365_connector=False,
        host_allowlist=[],
        host_denylist=[],
        ad_domain=None,
        business_unit=None,  # type: ignore[arg-type]
    )

    updated = _apply_config_defaults(intake, config)

    assert updated.authorized_scope == "local-host-only"
    assert updated.business_unit == ""
