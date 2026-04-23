from pathlib import Path

from app.scanners.nmap import findings_from_nmap_assets, parse_nmap_xml


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="host1.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_xml_parser_normalizes_assets_and_services() -> None:
    assets = parse_nmap_xml(NMAP_XML)

    assert len(assets) == 1
    assert assets[0].address == "192.168.1.10"
    assert assets[0].hostnames == ["host1.local"]
    assert [service.port for service in assets[0].services] == [3389, 80]


def test_nmap_findings_report_exposure_not_fake_cves() -> None:
    assets = parse_nmap_xml(NMAP_XML)
    findings = findings_from_nmap_assets(assets, Path("evidence/nmap.xml.enc"))

    assert len(findings) == 1
    assert findings[0].finding_basis == "network_discovery_evidence"
    assert findings[0].evidence_source_type == "nmap"
    assert "CVE" not in findings[0].title
    assert "vulnerability" not in findings[0].evidence_summary.lower()
