"""Scope guardrails for authorized assessments."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from app.core.input_normalization import normalize_prompt_value


LOCAL_ONLY_MARKERS = {"local", "localhost", "local-host-only", "host-only"}


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    """Represents operator-provided authorized multi-host scope."""

    raw_scope: str
    networks: tuple[ipaddress._BaseNetwork, ...]
    local_only: bool
    host_allowlist: tuple[str, ...] = ()
    host_denylist: tuple[str, ...] = ()
    ad_domain: str = ""
    business_unit: str = ""
    scope_labels: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    @classmethod
    def parse(
        cls,
        raw_scope: str,
        *,
        host_allowlist: list[str] | tuple[str, ...] | None = None,
        host_denylist: list[str] | tuple[str, ...] | None = None,
        ad_domain: str = "",
        business_unit: str = "",
        scope_labels: dict[str, str] | None = None,
    ) -> "ScopePolicy":
        cleaned = normalize_prompt_value(raw_scope)
        if not cleaned:
            raise ValueError("Authorized scope is mandatory.")

        allowlist = tuple(_split_items(host_allowlist))
        denylist = tuple(_split_items(host_denylist))
        labels = tuple(sorted((scope_labels or {}).items()))

        if cleaned.lower() in LOCAL_ONLY_MARKERS:
            return cls(
                raw_scope=cleaned,
                networks=(),
                local_only=True,
                host_allowlist=allowlist,
                host_denylist=denylist,
                ad_domain=normalize_prompt_value(ad_domain),
                business_unit=normalize_prompt_value(business_unit),
                scope_labels=labels,
            )

        networks: list[ipaddress._BaseNetwork] = []
        for candidate in _split_scope_entries(cleaned):
            try:
                networks.append(ipaddress.ip_network(candidate, strict=False))
            except ValueError as exc:
                raise ValueError(
                    f"Invalid scope entry '{candidate}'. Use CIDR or local-host-only."
                ) from exc
        if not networks:
            raise ValueError("Authorized scope did not contain a valid CIDR or local-host-only.")

        return cls(
            raw_scope=cleaned,
            networks=tuple(networks),
            local_only=False,
            host_allowlist=allowlist,
            host_denylist=denylist,
            ad_domain=normalize_prompt_value(ad_domain),
            business_unit=normalize_prompt_value(business_unit),
            scope_labels=labels,
        )

    def contains_ip(self, address: str) -> bool:
        if self.local_only:
            return address in {"127.0.0.1", "::1", "localhost"}
        ip = ipaddress.ip_address(address)
        return any(ip in network for network in self.networks)

    def allows_asset(self, address: str, hostnames: list[str] | tuple[str, ...] | None = None) -> bool:
        """Return true when a discovered asset is within scope and not denied."""

        normalized_hostnames = {item.strip().lower() for item in (hostnames or []) if item.strip()}
        address_lower = address.strip().lower()
        if not address_lower:
            return False
        if self.local_only:
            return address_lower in {"127.0.0.1", "::1", "localhost"}
        if address_lower in {item.lower() for item in self.host_denylist}:
            return False
        if normalized_hostnames & {item.lower() for item in self.host_denylist}:
            return False
        try:
            in_scope = self.contains_ip(address)
        except ValueError:
            in_scope = address_lower in {item.lower() for item in self.host_allowlist}
        if not in_scope and address_lower not in {item.lower() for item in self.host_allowlist}:
            return False
        if not self.host_allowlist:
            return True
        allowed = {item.lower() for item in self.host_allowlist}
        return address_lower in allowed or bool(normalized_hostnames & allowed)

    def scan_targets(self) -> list[str]:
        """Return canonical Nmap targets for the approved scope."""

        if self.local_only:
            return []
        return [str(network) for network in self.networks]

    def contains_network(self, network: str) -> bool:
        """Return true when a requested network is fully inside approved scope."""

        candidate = ipaddress.ip_network(network, strict=False)
        if self.local_only:
            return False
        return any(candidate.subnet_of(approved) for approved in self.networks)

    def validate_scan_targets(self, targets: list[str]) -> None:
        """Reject empty, invalid, or out-of-scope scan targets."""

        if not targets:
            raise ValueError("No approved scan targets are available.")
        for target in targets:
            if not self.contains_network(target):
                raise ValueError(f"Scan target outside approved scope: {target}")

    def label_for_ip(self, address: str) -> str:
        """Return the configured site label for an IP address when available."""

        if self.local_only:
            return "local"
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return ""
        for label_scope, label in self.scope_labels:
            try:
                candidate = ipaddress.ip_network(label_scope, strict=False)
            except ValueError:
                continue
            if ip in candidate:
                return label
        return ""

    def scope_summary(self) -> dict[str, object]:
        return {
            "raw_scope": self.raw_scope,
            "networks": [str(network) for network in self.networks],
            "local_only": self.local_only,
            "host_allowlist": list(self.host_allowlist),
            "host_denylist": list(self.host_denylist),
            "ad_domain": self.ad_domain,
            "business_unit": self.business_unit,
            "scope_labels": dict(self.scope_labels),
        }


def _split_scope_entries(raw_scope: str) -> list[str]:
    return _split_items(raw_scope.replace(";", ",").split(","))


def _split_items(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = value.replace(";", ",").split(",")
    elif isinstance(value, (list, tuple, set)):
        items = [str(item) for item in value]
    else:
        items = [str(value)]
    return [item.strip() for item in items if str(item).strip()]
