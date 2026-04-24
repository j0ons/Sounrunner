from app.core.models import Finding
from app.engine.correlation import correlate_findings


def test_correlation_merges_rdp_host_and_network_evidence() -> None:
    direct = Finding(
        finding_id="HOST-RDP-1",
        title="RDP is enabled on the host",
        category="Remote Access",
        package="standard",
        severity="high",
        confidence="confirmed",
        asset="server-01",
        evidence_summary="Registry and service evidence show RDP enabled.",
        evidence_files=["host.json"],
        why_it_matters="RDP broadens remote access exposure.",
        likely_business_impact="Remote access abuse could lead to compromise.",
        remediation_steps=["Restrict or disable RDP."],
        validation_steps=["Confirm RDP is disabled or controlled."],
        owner_role="Infrastructure",
        effort="medium",
        evidence_source_type="windows_native",
        evidence_collected_at="2026-01-01T00:00:00+00:00",
        raw_evidence_path="host.json",
        finding_basis="direct_system_evidence",
        risk_score=88,
    )
    network = Finding(
        finding_id="NMAP-RDP-1",
        title="RDP service exposed in approved scope",
        category="Network Discovery",
        package="standard",
        severity="high",
        confidence="strong",
        asset="server-01",
        evidence_summary="Nmap observed open tcp/3389.",
        evidence_files=["nmap.xml"],
        why_it_matters="Exposed administrative services increase attack surface.",
        likely_business_impact="Attackers can target RDP if other controls are weak.",
        remediation_steps=["Restrict RDP to approved sources."],
        validation_steps=["Re-run approved scope scan."],
        owner_role="Infrastructure",
        effort="medium",
        evidence_source_type="nmap",
        evidence_collected_at="2026-01-01T00:00:00+00:00",
        raw_evidence_path="nmap.xml",
        finding_basis="network_discovery_evidence",
        risk_score=82,
    )

    result = correlate_findings([direct, network])

    assert result.merged_count == 1
    assert result.suppressed_count == 1
    assert len(result.findings) == 1
    merged = result.findings[0]
    assert merged.title == "RDP exposure confirmed by correlated evidence"
    assert merged.correlation_key == "rdp_exposure"
    assert set(merged.merged_finding_ids) == {"HOST-RDP-1", "NMAP-RDP-1"}
    assert set(merged.merged_evidence_sources) == {
        "direct_system_evidence/windows_native",
        "network_discovery_evidence/nmap",
    }
    assert set(merged.evidence_files) == {"host.json", "nmap.xml"}


def test_correlation_preserves_unrelated_findings() -> None:
    backup = Finding(
        finding_id="BACKUP-1",
        title="Backup job failure imported from backup platform evidence",
        category="Backup Platform Evidence",
        package="standard",
        severity="medium",
        confidence="strong",
        asset="server-02",
        evidence_summary="status=failed",
        evidence_files=["backup.json"],
        why_it_matters="Backups failed.",
        likely_business_impact="Recovery may fail.",
        remediation_steps=["Fix backup job."],
        validation_steps=["Confirm successful backup."],
        owner_role="Backup Owner",
        effort="medium",
        evidence_source_type="backup_platform_import",
        evidence_collected_at="2026-01-01T00:00:00+00:00",
        raw_evidence_path="backup.json",
        finding_basis="imported_configuration_evidence",
        risk_score=60,
    )
    firewall = Finding(
        finding_id="FW-1",
        title="Administrative interface exposure imported from firewall/VPN evidence",
        category="Imported Configuration",
        package="standard",
        severity="high",
        confidence="strong",
        asset="edge-fw-01",
        evidence_summary="admin interface exposed",
        evidence_files=["fw.json"],
        why_it_matters="Exposed admin interfaces raise perimeter risk.",
        likely_business_impact="Administrative compromise could follow.",
        remediation_steps=["Restrict admin access."],
        validation_steps=["Review firewall export."],
        owner_role="Network Owner",
        effort="medium",
        evidence_source_type="firewall_vpn_import",
        evidence_collected_at="2026-01-01T00:00:00+00:00",
        raw_evidence_path="fw.json",
        finding_basis="imported_configuration_evidence",
        risk_score=85,
    )

    result = correlate_findings([backup, firewall])

    assert result.merged_count == 0
    assert result.suppressed_count == 0
    assert {item.finding_id for item in result.findings} == {"BACKUP-1", "FW-1"}
