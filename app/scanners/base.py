"""Scanner abstraction layer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

from app.core.models import Finding
from app.core.scope import ScopePolicy


@dataclass(slots=True)
class NetworkService:
    protocol: str
    port: int
    state: str
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class NetworkAsset:
    address: str
    hostnames: list[str] = field(default_factory=list)
    status: str = "unknown"
    services: list[NetworkService] = field(default_factory=list)
    mac_address: str = ""
    os_family: str = ""
    os_guess: str = ""
    discovery_source: str = "nmap"

    @property
    def primary_hostname(self) -> str:
        return self.hostnames[0] if self.hostnames else ""

    @property
    def service_ports(self) -> list[int]:
        return sorted({service.port for service in self.services})


@dataclass(slots=True)
class ScannerResult:
    scanner_name: str
    status: str
    detail: str
    assets: list[NetworkAsset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    raw_evidence_path: Path | None = None


class ScannerAdapter(Protocol):
    name: str

    def scan(self, scope: ScopePolicy) -> ScannerResult:
        """Run or import scanner evidence for the approved scope."""
