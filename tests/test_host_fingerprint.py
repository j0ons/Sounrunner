from __future__ import annotations

from app.core.inventory import AssetRecord
from app.engine.host_fingerprint import fingerprint_host


def test_smb_only_host_is_probable_windows_without_winrm() -> None:
    fp = fingerprint_host(
        AssetRecord(asset_id="a1", hostname="files01"),
        [_service(445, "microsoft-ds")],
    )

    assert fp.classification == "probable_windows"
    assert fp.has_winrm is False


def test_rdp_host_is_probable_windows_without_winrm() -> None:
    fp = fingerprint_host(
        AssetRecord(asset_id="a1", hostname="desktop01"),
        [_service(3389, "ms-wbt-server", product="Microsoft Terminal Services")],
    )

    assert fp.classification == "probable_windows"
    assert fp.has_winrm is False


def test_winrm_host_is_probable_windows_and_remote_candidate() -> None:
    fp = fingerprint_host(
        AssetRecord(asset_id="a1", hostname="server01"),
        [_service(5985, "wsman", product="Microsoft HTTPAPI httpd")],
    )

    assert fp.classification == "probable_windows"
    assert fp.has_winrm is True


def test_openssh_only_host_is_probable_linux_unix() -> None:
    fp = fingerprint_host(
        AssetRecord(asset_id="a1", hostname="linux01"),
        [_service(22, "ssh", product="OpenSSH")],
    )

    assert fp.classification == "probable_linux_unix"
    assert fp.has_winrm is False


def test_infra_hostname_with_snmp_https_ssh_is_network_device() -> None:
    fp = fingerprint_host(
        AssetRecord(asset_id="a1", hostname="core-switch-01"),
        [
            _service(22, "ssh"),
            _service(443, "https"),
            _service(161, "snmp"),
        ],
    )

    assert fp.classification == "probable_network_device"


def _service(port: int, service_name: str, *, product: str = "", state: str = "open") -> dict[str, object]:
    return {
        "port": port,
        "protocol": "tcp",
        "state": state,
        "service_name": service_name,
        "product": product,
        "version": "",
        "extra_info": "",
    }
