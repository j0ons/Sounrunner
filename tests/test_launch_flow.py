from __future__ import annotations

from pathlib import Path

import pytest

from app.core.auto_context import AutoEnterpriseContext, DetectedInterface
from app.core.config import AppConfig
from app.core.session import AssessmentIntake
from app.ui.console import ConsoleUi
from main import _launch_warnings, _resolve_intake, build_parser


class DummyUi:
    def __init__(self, result: AssessmentIntake | None = None) -> None:
        self.called = False
        self.seed: AssessmentIntake | None = None
        self.result = result

    def complete_intake(self, seed: AssessmentIntake, *, prompt_optional: bool = False) -> AssessmentIntake:
        self.called = True
        self.seed = seed
        assert prompt_optional is False
        if self.result is not None:
            return self.result
        return seed


def test_non_interactive_config_first_launch_uses_config_without_prompt(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
read_only: true
assessment:
  client_name: "Contoso"
  site: "HQ"
  operator_name: "Operator"
  package: "standard"
  consent_confirmed: true
  approved_scopes:
    - "10.0.0.0/24"
""",
        encoding="utf-8",
    )
    config = AppConfig.load(config_file)
    args = build_parser().parse_args(["--config", str(config_file), "--non-interactive", "--scope-from-config"])
    ui = DummyUi()

    intake = _resolve_intake(args=args, config=config, ui=ui, auto_context=_auto_context())  # type: ignore[arg-type]

    assert ui.called is False
    assert intake.client_name == "Contoso"
    assert intake.site == "HQ"
    assert intake.operator_name == "Operator"
    assert intake.package == "standard"
    assert intake.authorized_scope == "10.0.0.0/24"
    assert intake.consent_confirmed is True


def test_interactive_launch_uses_config_without_prompt_when_ready(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
read_only: true
assessment:
  client_name: "Contoso"
  site: "HQ"
  operator_name: "Analyst"
  package: "advanced"
  consent_confirmed: true
  approved_scopes:
    - "10.0.0.0/24"
""",
        encoding="utf-8",
    )
    config = AppConfig.load(config_file)
    args = build_parser().parse_args(["--config", str(config_file)])
    ui = DummyUi()

    intake = _resolve_intake(args=args, config=config, ui=ui, auto_context=_auto_context())  # type: ignore[arg-type]

    assert ui.called is False
    assert intake.operator_name == "Analyst"
    assert intake.authorized_scope == "10.0.0.0/24"


def test_interactive_launch_prompts_only_for_missing_company_or_package(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
read_only: true
assessment:
  site: "HQ"
  consent_confirmed: true
  approved_scopes:
    - "10.0.0.0/24"
""",
        encoding="utf-8",
    )
    config = AppConfig.load(config_file)
    args = build_parser().parse_args(["--config", str(config_file)])
    resolved = AssessmentIntake(
        client_name="Contoso",
        site="HQ",
        operator_name="Analyst",
        package="advanced",
        authorized_scope="10.0.0.0/24",
        scope_notes="No additional notes.",
        consent_confirmed=True,
    )
    ui = DummyUi(result=resolved)

    intake = _resolve_intake(args=args, config=config, ui=ui, auto_context=_auto_context())  # type: ignore[arg-type]

    assert ui.called is True
    assert ui.seed is not None
    assert ui.seed.client_name == ""
    assert ui.seed.package == ""
    assert ui.seed.authorized_scope == "10.0.0.0/24"
    assert intake.client_name == "Contoso"


def test_non_interactive_launch_fails_cleanly_on_missing_values(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("read_only: true\nassessment: {}\n", encoding="utf-8")
    config = AppConfig.load(config_file)
    args = build_parser().parse_args(["--config", str(config_file), "--non-interactive"])

    with pytest.raises(ValueError, match="missing client_name"):
        _resolve_intake(args=args, config=config, ui=DummyUi(), auto_context=_auto_context())  # type: ignore[arg-type]


def test_non_interactive_cli_consent_flag_satisfies_launch_validation(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
read_only: true
assessment:
  client_name: "Contoso"
  site: "HQ"
  operator_name: "Operator"
  package: "standard"
  approved_scopes:
    - "10.0.0.0/24"
""",
        encoding="utf-8",
    )
    config = AppConfig.load(config_file)
    args = build_parser().parse_args(
        ["--config", str(config_file), "--non-interactive", "--consent-confirmed"]
    )

    intake = _resolve_intake(args=args, config=config, ui=DummyUi(), auto_context=_auto_context())  # type: ignore[arg-type]

    assert intake.consent_confirmed is True


def test_non_interactive_launch_uses_auto_detected_scope_when_config_scope_missing(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
read_only: true
assessment:
  client_name: "Contoso"
  site: "HQ"
  operator_name: "Operator"
  package: "standard"
  consent_confirmed: true
""",
        encoding="utf-8",
    )
    config = AppConfig.load(config_file)
    args = build_parser().parse_args(["--config", str(config_file), "--non-interactive"])

    intake = _resolve_intake(args=args, config=config, ui=DummyUi(), auto_context=_auto_context())  # type: ignore[arg-type]

    assert intake.authorized_scope == "10.20.30.0/24"


def test_non_interactive_cli_company_name_alias() -> None:
    config = AppConfig()
    args = build_parser().parse_args(
        [
            "--company-name",
            "Contoso",
            "--package",
            "standard",
            "--non-interactive",
            "--consent-confirmed",
        ]
    )

    intake = _resolve_intake(args=args, config=config, ui=DummyUi(), auto_context=_auto_context())  # type: ignore[arg-type]

    assert intake.client_name == "Contoso"
    assert intake.package == "standard"
    assert intake.authorized_scope == "10.20.30.0/24"


def test_interactive_launch_fails_cleanly_on_invalid_config_scope(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
read_only: true
assessment:
  client_name: "Contoso"
  package: "standard"
  consent_confirmed: true
  approved_scope: "CIDR"
""",
        encoding="utf-8",
    )
    config = AppConfig.load(config_file)
    args = build_parser().parse_args(["--config", str(config_file)])

    with pytest.raises(ValueError, match="Launch validation failed"):
        _resolve_intake(args=args, config=config, ui=DummyUi(), auto_context=_auto_context())  # type: ignore[arg-type]


def test_interactive_launch_fails_cleanly_on_invalid_config_allowlist(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
read_only: true
assessment:
  client_name: "Contoso"
  package: "standard"
  consent_confirmed: true
  approved_scope: "10.0.0.0/24"
  host_allowlist:
    - "CIDR"
""",
        encoding="utf-8",
    )
    config = AppConfig.load(config_file)
    args = build_parser().parse_args(["--config", str(config_file)])

    with pytest.raises(ValueError, match="Launch validation failed"):
        _resolve_intake(args=args, config=config, ui=DummyUi(), auto_context=_auto_context())  # type: ignore[arg-type]


def test_launch_warnings_flag_limited_standard_scope() -> None:
    config = AppConfig()
    intake = AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="local-host-only",
        scope_notes="test",
        consent_confirmed=True,
    )

    warnings = _launch_warnings(intake, config)

    assert any("localhost-only scope" in item for item in warnings)
    assert any("no configured credential path" in item for item in warnings)


def test_visual_launch_summary_handles_non_rich_console(capsys) -> None:
    ui = ConsoleUi(app_version="test")
    ui.console = None
    intake = AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="10.0.0.0/24",
        scope_notes="test",
        consent_confirmed=True,
    )

    ui.print_launch_summary(
        intake,
        non_interactive=True,
        report_mode="standard",
        warnings=["limited"],
        context={"scope_source": "auto_detected_local_subnets"},
    )

    output = capsys.readouterr().out
    assert "Run Contract" in output
    assert "headless" in output
    assert "auto_detected_local_subnets" in output
    assert "limited" in output


def _auto_context(
    *,
    scope: str = "10.20.30.0/24",
    source: str = "auto_detected_local_subnets",
) -> AutoEnterpriseContext:
    return AutoEnterpriseContext(
        hostname="runner01",
        fqdn="runner01.corp.example.com",
        operator_name="DetectedOperator",
        os_name="Windows",
        domain_joined=True,
        domain_name="corp.example.com",
        dns_suffixes=["corp.example.com"],
        interfaces=[
            DetectedInterface(
                name="Ethernet",
                ip_address="10.20.30.42",
                prefix_length=24,
                subnet="10.20.30.0/24",
                gateway="10.20.30.1",
                dns_suffix="corp.example.com",
            )
        ],
        private_subnets=[scope] if scope != "local-host-only" else [],
        scope_source=source,
        default_scope=scope,
        site_label="CORP",
        business_unit="",
        email_domain="corp.example.com",
        ad_domain="corp.example.com",
        warnings=[],
    )
