from app.scanners.greenbone_import import parse_greenbone_xml
from app.scanners.nessus_import import parse_nessus_xml


NESSUS_XML = """<NessusClientData_v2>
<Report name="test">
  <ReportHost name="host1">
    <HostProperties><tag name="host-ip">192.168.1.10</tag></HostProperties>
    <ReportItem port="445" protocol="tcp" severity="3" pluginID="1001" pluginName="SMB Signing Disabled">
      <risk_factor>High</risk_factor>
      <description>SMB signing is not required.</description>
      <solution>Require SMB signing.</solution>
    </ReportItem>
  </ReportHost>
</Report>
</NessusClientData_v2>"""


GREENBONE_XML = """<report>
<results>
  <result>
    <host>192.168.1.11</host>
    <port>80/tcp</port>
    <name>Outdated web server</name>
    <threat>Medium</threat>
    <severity>5.0</severity>
    <description>Detected outdated version.</description>
    <solution>Update the service.</solution>
  </result>
</results>
</report>"""


def test_nessus_import_parser_maps_findings() -> None:
    findings = parse_nessus_xml(NESSUS_XML, "nessus.xml.enc")

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].finding_basis == "imported_scanner_evidence"
    assert findings[0].evidence_source_type == "nessus"


def test_greenbone_import_parser_maps_findings() -> None:
    findings = parse_greenbone_xml(GREENBONE_XML, "greenbone.xml.enc")

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].finding_basis == "imported_scanner_evidence"
    assert findings[0].evidence_source_type == "greenbone"
