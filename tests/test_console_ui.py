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


def test_collect_intake_only_prompts_for_company_and_package(monkeypatch) -> None:
    ui = ConsoleUi(app_version="test")
    ui.console = None
    monkeypatch.setattr("app.ui.console.getpass.getuser", lambda: "DetectedOperator")
    _set_inputs(monkeypatch, ["Client", "standard"])

    intake = ui.collect_intake()

    assert intake.client_name == "Client"
    assert intake.package == "standard"
    assert intake.site == "Auto-detected"
    assert intake.operator_name == "DetectedOperator"
    assert intake.authorized_scope == "local-host-only"
    assert intake.consent_confirmed is True


def test_interactive_package_menu_appears_when_package_missing(monkeypatch, capsys) -> None:
    ui = ConsoleUi(app_version="test")
    ui.console = None
    _set_inputs(monkeypatch, ["Client", ""])

    intake = ui.collect_intake()
    output = capsys.readouterr().out

    assert intake.package == "standard"
    assert "Assessment package:" in output
    assert "[1] Basic" in output
    assert "[2] Standard" in output
    assert "[3] Advanced" in output


def test_collect_intake_reprompts_invalid_package(monkeypatch, capsys) -> None:
    ui = ConsoleUi(app_version="test")
    ui.console = None
    _set_inputs(monkeypatch, ["Client", "wrong", "advanced"])

    intake = ui.collect_intake()

    assert intake.package == "advanced"
    assert "Invalid package selection. Enter 1/basic, 2/standard, or 3/advanced." in capsys.readouterr().out


def test_complete_intake_drops_invalid_allowlist_seed_without_prompt(monkeypatch, capsys) -> None:
    ui = ConsoleUi(app_version="test")
    ui.console = None
    _set_inputs(monkeypatch, [])
    seed = AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="basic",
        authorized_scope="local-host-only",
        scope_notes="No additional notes.",
        consent_confirmed=True,
        host_allowlist=["CIDR"],
        host_denylist=["server01"],
    )

    intake = ui.complete_intake(seed)

    assert intake.host_allowlist == []
    assert intake.host_denylist == ["server01"]
    assert (
        "Invalid host entry 'CIDR'. Expected IP address, hostname, or FQDN. "
        "Put CIDR ranges in Authorized scope/subnet."
    ) in capsys.readouterr().out


def test_collect_intake_blank_optional_fields_are_normalized(monkeypatch) -> None:
    ui = ConsoleUi(app_version="test")
    ui.console = None
    _set_inputs(monkeypatch, ["Client", "basic"])

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
    monkeypatch.setattr("app.ui.console.getpass.getuser", lambda: "Operator")
    _set_inputs(monkeypatch, [" Client ", "1"])

    intake = ui.collect_intake()

    assert intake.client_name == "Client"
    assert intake.site == "Auto-detected"
    assert intake.operator_name == "Operator"
    assert intake.package == "basic"
    assert intake.authorized_scope == "local-host-only"
    assert intake.ad_domain is None
    assert intake.business_unit == ""
    assert intake.domain is None
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
