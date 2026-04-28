"""Service-based host fingerprinting for safe remote collection planning."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.inventory import AssetRecord


WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986}
WINRM_PORTS = {5985, 5986}
NETWORK_DEVICE_PORTS = {22, 80, 443, 161, 830, 8443}
STORAGE_PORTS = {111, 2049, 548, 873, 5000, 5001}


@dataclass(frozen=True, slots=True)
class HostFingerprint:
    """Observed host OS/platform classification without claiming full assessment."""

    classification: str
    confidence: str
    indicators: tuple[str, ...]
    has_winrm: bool = False

    @property
    def is_windows_like(self) -> bool:
        return self.classification in {"confirmed_windows", "probable_windows"}

    def to_dict(self, asset: AssetRecord) -> dict[str, object]:
        return {
            "asset_id": asset.asset_id,
            "asset": asset.display_name,
            "ip_address": asset.ip_address,
            "classification": self.classification,
            "confidence": self.confidence,
            "indicators": list(self.indicators),
            "has_winrm": self.has_winrm,
        }


def fingerprint_host(record: AssetRecord, services: list[dict[str, Any]]) -> HostFingerprint:
    """Classify a host from read-only discovery evidence and existing metadata."""

    ports = {
        int(item.get("port", 0))
        for item in services
        if str(item.get("state", "")).lower() in {"open", "open|filtered", ""}
    }
    service_blob = " ".join(
        " ".join(
            [
                str(item.get("service_name", "")),
                str(item.get("product", "")),
                str(item.get("version", "")),
                str(item.get("extra_info", "")),
            ]
        )
        for item in services
    ).lower()
    asset_blob = f"{record.hostname} {record.fqdn} {record.asset_role}".lower()
    os_blob = f"{record.os_family} {record.os_guess}".lower()
    indicators: list[str] = []

    if _has_confirmed_windows_metadata(os_blob):
        indicators.append("existing OS metadata contains Windows")
        return HostFingerprint(
            classification="confirmed_windows",
            confidence="strong",
            indicators=tuple(indicators),
            has_winrm=bool(ports & WINRM_PORTS),
        )

    if _looks_like_network_device(record, ports, service_blob):
        indicators.append("hostname/service pattern indicates network infrastructure")
        return HostFingerprint(
            classification="probable_network_device",
            confidence="moderate",
            indicators=tuple(indicators),
            has_winrm=bool(ports & WINRM_PORTS),
        )

    windows_hits = sorted(ports & WINDOWS_PORTS)
    if windows_hits:
        indicators.append("Windows-associated port(s): " + ",".join(str(port) for port in windows_hits))
    if _has_microsoft_indicator(service_blob):
        indicators.append("Microsoft service/product/banner indicator")
    if indicators:
        return HostFingerprint(
            classification="probable_windows",
            confidence="moderate" if len(indicators) == 1 else "strong",
            indicators=tuple(indicators),
            has_winrm=bool(ports & WINRM_PORTS),
        )

    if _looks_like_storage(record, ports, service_blob):
        indicators.append("storage/NAS service or hostname indicator")
        return HostFingerprint(
            classification="probable_storage",
            confidence="moderate",
            indicators=tuple(indicators),
            has_winrm=False,
        )

    if _looks_like_linux_unix(ports, service_blob):
        indicators.append("OpenSSH/Unix-like service indicator without Windows signals")
        return HostFingerprint(
            classification="probable_linux_unix",
            confidence="moderate",
            indicators=tuple(indicators),
            has_winrm=False,
        )

    return HostFingerprint(
        classification="unknown",
        confidence="weak",
        indicators=(),
        has_winrm=False,
    )


def _has_microsoft_indicator(blob: str) -> bool:
    return any(
        token in blob
        for token in [
            "microsoft",
            "microsoft-ds",
            "msrpc",
            "ms-wbt-server",
            "netbios",
            "wsman",
            "winrm",
            "windows",
        ]
    )


def _has_confirmed_windows_metadata(blob: str) -> bool:
    """Return true only for OS metadata, not prior probable labels."""

    normalized = " ".join(blob.split())
    if not normalized or "probable_windows" in normalized:
        return False
    if normalized in {"windows", "microsoft windows"}:
        return True
    return any(
        token in normalized
        for token in [
            "microsoft windows",
            "windows server",
            "windows 11",
            "windows 10",
            "windows 8",
            "windows 7",
            "windows nt",
        ]
    )


def _looks_like_network_device(record: AssetRecord, ports: set[int], service_blob: str) -> bool:
    hint = f"{record.hostname} {record.fqdn} {record.asset_role} {service_blob}".lower()
    if record.asset_role == "network_device":
        return True
    infra_tokens = ["fw", "firewall", "router", "switch", "core", "wlan", "controller", "ap-", "ap.", "printer"]
    return bool((ports & NETWORK_DEVICE_PORTS) and any(token in hint for token in infra_tokens))


def _looks_like_storage(record: AssetRecord, ports: set[int], service_blob: str) -> bool:
    hint = f"{record.hostname} {record.fqdn} {record.asset_role} {service_blob}".lower()
    storage_tokens = ["nas", "storage", "synology", "qnap", "truenas", "freenas"]
    return bool((ports & STORAGE_PORTS) or any(token in hint for token in storage_tokens))


def _looks_like_linux_unix(ports: set[int], service_blob: str) -> bool:
    if "openssh" in service_blob or "ubuntu" in service_blob or "debian" in service_blob or "linux" in service_blob:
        return True
    return ports == {22} or bool(22 in ports and not (ports & WINDOWS_PORTS))
