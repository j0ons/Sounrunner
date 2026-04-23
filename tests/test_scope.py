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


def test_scope_rejects_invalid_input() -> None:
    with pytest.raises(ValueError):
        ScopePolicy.parse("entire internet")
