from __future__ import annotations

from pathlib import Path

import pytest

from app.core.auto_context import AutoEnterpriseContext, DetectedInterface
from app.core.config import AppConfig
from app.core.session import AssessmentIntake
from app.ui.console import ConsoleUi
from main import _apply_cli_scope_override, _launch_warnings, _mark_cli_scope, _resolve_intake, build_parser


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


def test_interactive_launch_ignores_config_package_and_prompts(tmp_path: Path) -> None:
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
    resolved = AssessmentIntake(
        client_name="Contoso",
        site="HQ",
        operator_name="Analyst",
        package="standard",
        authorized_scope="10.0.0.0/24",
        scope_notes="No additional notes.",
        consent_confirmed=True,
    )
    ui = DummyUi(result=resolved)

    intake = _resolve_intake(args=args, config=config, ui=ui, auto_context=_auto_context())  # type: ignore[arg-type]

    assert ui.called is True
    assert ui.seed is not None
    assert ui.seed.package == ""
    assert intake.operator_name == "Analyst"
    assert intake.package == "standard"
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


def test_cli_package_skips_package_prompt() -> None:
    config = AppConfig()
    args = build_parser().parse_args(
        [
            "--company-name",
            "Contoso",
            "--package",
            "advanced",
            "--consent-confirmed",
        ]
    )
    ui = DummyUi()

    intake = _resolve_intake(args=args, config=config, ui=ui, auto_context=_auto_context())  # type: ignore[arg-type]

    assert ui.called is False
    assert intake.package == "advanced"


def test_config_package_used_in_non_interactive_mode() -> None:
    config = AppConfig()
    config.assessment.client_name = "Contoso"
    config.assessment.package = "standard"
    config.assessment.consent_confirmed = True
    args = build_parser().parse_args(["--non-interactive"])

    intake = _resolve_intake(args=args, config=config, ui=DummyUi(), auto_context=_auto_context())  # type: ignore[arg-type]

    assert intake.package == "standard"


def test_basic_selected_allows_local_endpoint_mode() -> None:
    config = AppConfig()
    args = build_parser().parse_args(
        [
            "--company-name",
            "Contoso",
            "--package",
            "basic",
            "--non-interactive",
            "--consent-confirmed",
        ]
    )

    intake = _resolve_intake(
        args=args,
        config=config,
        ui=DummyUi(),
        auto_context=_auto_context(scope="local-host-only", source="localhost_only_fallback"),
    )  # type: ignore[arg-type]

    assert intake.package == "basic"
    assert intake.authorized_scope == "local-host-only"


def test_interactive_standard_scope_prompt_when_auto_scope_fails() -> None:
    class ScopeUi(DummyUi):
        def ask_approved_scope(self, package: str) -> str:
            assert package == "standard"
            return "10.0.180.0/24"

    config = AppConfig()
    args = build_parser().parse_args(
        [
            "--company-name",
            "Contoso",
            "--package",
            "standard",
            "--consent-confirmed",
        ]
    )
    context = _auto_context(scope="local-host-only", source="localhost_only_fallback")

    intake = _resolve_intake(args=args, config=config, ui=ScopeUi(), auto_context=context)  # type: ignore[arg-type]

    assert intake.package == "standard"
    assert intake.authorized_scope == "10.0.180.0/24"
    assert context.scope_source == "cli_scope"


def test_cli_approved_scope_overrides_auto_detected_scope() -> None:
    config = AppConfig()
    args = build_parser().parse_args(
        [
            "--company-name",
            "Contoso",
            "--package",
            "standard",
            "--approved-scope",
            "10.0.180.0/24",
            "--non-interactive",
            "--consent-confirmed",
        ]
    )
    cli_scope = _apply_cli_scope_override(args, config)
    context = _auto_context(scope="10.20.30.0/24")
    _mark_cli_scope(context, cli_scope)

    intake = _resolve_intake(args=args, config=config, ui=DummyUi(), auto_context=context)  # type: ignore[arg-type]

    assert intake.authorized_scope == "10.0.180.0/24"
    assert context.scope_source == "cli_scope"
    assert context.default_scope == "10.0.180.0/24"


def test_config_scope_beats_failed_auto_scope() -> None:
    config = AppConfig()
    config.assessment.client_name = "Contoso"
    config.assessment.package = "standard"
    config.assessment.consent_confirmed = True
    config.assessment.approved_scopes = ["10.0.180.0/24"]
    args = build_parser().parse_args(["--non-interactive"])

    intake = _resolve_intake(
        args=args,
        config=config,
        ui=DummyUi(),
        auto_context=_auto_context(scope="local-host-only", source="localhost_only_fallback"),
    )  # type: ignore[arg-type]

    assert intake.authorized_scope == "10.0.180.0/24"


def test_standard_blocks_localhost_fallback_by_default() -> None:
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

    with pytest.raises(ValueError, match="localhost-only fallback is blocked"):
        _resolve_intake(
            args=args,
            config=config,
            ui=DummyUi(),
            auto_context=_auto_context(scope="local-host-only", source="localhost_only_fallback"),
        )  # type: ignore[arg-type]


def test_interactive_prompt_result_requests_scope_for_standard_localhost() -> None:
    class ScopeUi(DummyUi):
        def ask_approved_scope(self, package: str) -> str:
            assert package == "standard"
            return "10.0.180.0/24"

    config = AppConfig()
    args = build_parser().parse_args([])
    resolved = AssessmentIntake(
        client_name="Contoso",
        site="Local Network",
        operator_name="Operator",
        package="standard",
        authorized_scope="local-host-only",
        scope_notes="test",
        consent_confirmed=True,
    )

    intake = _resolve_intake(
        args=args,
        config=config,
        ui=ScopeUi(result=resolved),
        auto_context=_auto_context(scope="local-host-only", source="localhost_only_fallback"),
    )  # type: ignore[arg-type]

    assert intake.authorized_scope == "10.0.180.0/24"


def test_standard_allows_localhost_fallback_when_explicitly_configured() -> None:
    config = AppConfig()
    config.assessment.allow_localhost_fallback_for_company_modes = True
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

    intake = _resolve_intake(
        args=args,
        config=config,
        ui=DummyUi(),
        auto_context=_auto_context(scope="local-host-only", source="localhost_only_fallback"),
    )  # type: ignore[arg-type]

    assert intake.authorized_scope == "local-host-only"


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
    assert "Company: Client" in output
    assert "Package: standard" in output
    assert "Mode: Standard company-level" in output
    assert "Scope: 10.0.0.0/24" in output
    assert "headless" in output
    assert "auto_detected_local_subnets" in output
    assert "Network assessment: enabled" in output
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
