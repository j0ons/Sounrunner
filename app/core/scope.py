"""Scope guardrails for authorized assessments."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    """Represents operator-provided authorized scope."""

    raw_scope: str
    networks: tuple[ipaddress._BaseNetwork, ...]
    local_only: bool

    @classmethod
    def parse(cls, raw_scope: str) -> "ScopePolicy":
        cleaned = raw_scope.strip()
        if not cleaned:
            raise ValueError("Authorized scope is mandatory.")
        if cleaned.lower() in {"local", "localhost", "local-host-only", "host-only"}:
            return cls(raw_scope=cleaned, networks=(), local_only=True)

        networks: list[ipaddress._BaseNetwork] = []
        for part in cleaned.replace(";", ",").split(","):
            candidate = part.strip()
            if not candidate:
                continue
            try:
                networks.append(ipaddress.ip_network(candidate, strict=False))
            except ValueError as exc:
                raise ValueError(
                    f"Invalid scope entry '{candidate}'. Use CIDR or local-host-only."
                ) from exc
        if not networks:
            raise ValueError("Authorized scope did not contain a valid CIDR or local-host-only.")
        return cls(raw_scope=cleaned, networks=tuple(networks), local_only=False)

    def contains_ip(self, address: str) -> bool:
        if self.local_only:
            return address in {"127.0.0.1", "::1", "localhost"}
        ip = ipaddress.ip_address(address)
        return any(ip in network for network in self.networks)
