from app.modules.email_security import build_email_findings


def test_email_findings_mark_unknown_dkim_as_partial_not_failure() -> None:
    findings = build_email_findings(
        domain="example.com",
        evidence={
            "spf": {"records": ["v=spf1 include:spf.example.com -all"]},
            "dmarc": {"records": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]},
            "dkim_selectors_configured": [],
            "dkim": {},
        },
        evidence_path="evidence/email.json.enc",
        collected_at="2026-04-23T00:00:00+00:00",
    )

    assert len(findings) == 1
    assert findings[0].finding_id == "BASIC-EMAIL-005"
    assert findings[0].finding_basis == "inferred_partial"
    assert findings[0].confidence == "weak"


def test_email_findings_are_based_on_dns_records() -> None:
    findings = build_email_findings(
        domain="example.com",
        evidence={
            "spf": {"records": []},
            "dmarc": {"records": []},
            "dkim_selectors_configured": ["selector1"],
            "dkim": {"selector1": {"records": []}},
        },
        evidence_path="evidence/email.json.enc",
        collected_at="2026-04-23T00:00:00+00:00",
    )

    finding_ids = {finding.finding_id for finding in findings}
    assert "BASIC-EMAIL-001" in finding_ids
    assert "BASIC-EMAIL-003" in finding_ids
    assert "BASIC-EMAIL-006" in finding_ids
    assert all(finding.evidence_source_type == "dns" for finding in findings)
