import pytest

from app.core.scope import ScopePolicy


def test_scope_accepts_local_only() -> None:
    scope = ScopePolicy.parse("local-host-only")
    assert scope.local_only is True
    assert scope.contains_ip("127.0.0.1") is True


def test_scope_accepts_cidr() -> None:
    scope = ScopePolicy.parse("192.168.1.0/24")
    assert scope.local_only is False
    assert scope.contains_ip("192.168.1.10") is True
    assert scope.contains_ip("10.0.0.1") is False
    assert scope.scan_targets() == ["192.168.1.0/24"]
    scope.validate_scan_targets(["192.168.1.0/25"])


def test_scope_rejects_invalid_input() -> None:
    with pytest.raises(ValueError):
        ScopePolicy.parse("entire internet")


def test_scope_rejects_out_of_scope_scan_target() -> None:
    scope = ScopePolicy.parse("192.168.1.0/24")
    with pytest.raises(ValueError, match="outside approved scope"):
        scope.validate_scan_targets(["192.168.2.0/24"])


def test_scope_supports_multiple_subnets_and_host_filters() -> None:
    scope = ScopePolicy.parse(
        "10.0.0.0/24,10.0.1.0/24",
        host_allowlist=["srv-01", "10.0.1.20"],
        host_denylist=["10.0.0.5"],
        scope_labels={
            "10.0.0.0/24": "HQ",
            "10.0.1.0/24": "Branch",
        },
    )

    assert scope.scan_targets() == ["10.0.0.0/24", "10.0.1.0/24"]
    assert scope.allows_asset("10.0.1.20", ["srv-01"]) is True
    assert scope.allows_asset("10.0.0.5", []) is False
    assert scope.allows_asset("10.0.0.99", ["other-host"]) is False
    assert scope.label_for_ip("10.0.1.10") == "Branch"
