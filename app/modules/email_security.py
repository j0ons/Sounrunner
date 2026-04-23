"""SPF, DKIM, and DMARC DNS checks for Basic package."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.resolver

from app.core.config import EmailSecurityConfig
from app.core.evidence import confidence_for_basis, utc_now
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession
from app.profiling.environment import EnvironmentProfile


@dataclass(slots=True)
class EmailSecurityModule:
    session: AssessmentSession
    profile: EnvironmentProfile
    config: EmailSecurityConfig

    name: str = "email_security"

    def run(self) -> ModuleResult:
        domain = (self.session.intake.domain or "").strip().strip(".")
        if not domain:
            return ModuleResult(
                module_name=self.name,
                status="skipped",
                detail="No email domain provided. SPF/DKIM/DMARC checks skipped.",
            )

        collected_at = utc_now()
        evidence: dict[str, object] = {
            "domain": domain,
            "collected_at": collected_at,
            "spf": query_txt(domain, self.config.dns_timeout_seconds),
            "dmarc": query_txt(f"_dmarc.{domain}", self.config.dns_timeout_seconds),
            "dkim_selectors_configured": self.config.dkim_selectors,
            "dkim": {
                selector: query_txt(
                    f"{selector}._domainkey.{domain}",
                    self.config.dns_timeout_seconds,
                )
                for selector in self.config.dkim_selectors
            },
        }
        evidence_file = self.session.crypto.write_text(
            self.session.evidence_dir / "email_security_dns.json",
            json.dumps(evidence, indent=2, sort_keys=True),
        )

        findings = build_email_findings(
            domain=domain,
            evidence=evidence,
            evidence_path=str(evidence_file),
            collected_at=collected_at,
        )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail=(
                f"Checked SPF and DMARC for {domain}; "
                f"DKIM selectors checked: {len(self.config.dkim_selectors)}."
            ),
            findings=findings,
            evidence_files=[evidence_file],
        )


def query_txt(name: str, timeout_seconds: int) -> dict[str, object]:
    """Query TXT records and preserve resolver status for evidence."""

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout_seconds
    resolver.timeout = timeout_seconds
    try:
        answers = resolver.resolve(name, "TXT")
        records = [
            "".join(
                part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                for part in answer.strings
            )
            for answer in answers
        ]
        return {
            "name": name,
            "status": "ok",
            "records": records,
            "error": "",
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
        return {
            "name": name,
            "status": "no_records",
            "records": [],
            "error": exc.__class__.__name__,
        }
    except dns.exception.Timeout as exc:
        return {
            "name": name,
            "status": "timeout",
            "records": [],
            "error": str(exc),
        }
    except dns.exception.DNSException as exc:
        return {
            "name": name,
            "status": "error",
            "records": [],
            "error": str(exc),
        }


def build_email_findings(
    *,
    domain: str,
    evidence: dict[str, object],
    evidence_path: str,
    collected_at: str,
) -> list[Finding]:
    """Normalize DNS evidence into honest email security findings."""

    findings: list[Finding] = []
    spf_records = _records_containing(_records(evidence["spf"]), "v=spf1")
    dmarc_records = _records_containing(_records(evidence["dmarc"]), "v=DMARC1")
    dkim_evidence = evidence.get("dkim", {})
    dkim_records: dict[str, list[str]] = {}
    if isinstance(dkim_evidence, dict):
        for selector, payload in dkim_evidence.items():
            dkim_records[str(selector)] = _records_containing(_records(payload), "v=DKIM1")

    if not spf_records:
        findings.append(
            _email_finding(
                finding_id="BASIC-EMAIL-001",
                title="SPF record not confirmed",
                severity="medium",
                confidence=confidence_for_basis("direct_system_evidence"),
                domain=domain,
                evidence_summary="DNS TXT lookup did not confirm a v=spf1 record.",
                why_it_matters="Missing SPF weakens sender authentication and increases spoofing risk.",
                likely_business_impact="Attackers can more easily impersonate the organization in phishing.",
                remediation_steps=[
                    "Publish a valid SPF record for approved mail sources.",
                    "Keep the SPF lookup count within DNS limits.",
                ],
                validation_steps=[
                    "Query the domain TXT records and confirm one valid v=spf1 record.",
                ],
                evidence_path=evidence_path,
                collected_at=collected_at,
                basis="direct_system_evidence",
            )
        )
    elif len(spf_records) > 1:
        findings.append(
            _email_finding(
                finding_id="BASIC-EMAIL-002",
                title="Multiple SPF records detected",
                severity="medium",
                confidence=confidence_for_basis("direct_system_evidence"),
                domain=domain,
                evidence_summary=f"DNS TXT lookup returned {len(spf_records)} SPF records.",
                why_it_matters="Multiple SPF records can cause SPF evaluation failures.",
                likely_business_impact="Legitimate mail may fail authentication and spoofing protection may be inconsistent.",
                remediation_steps=[
                    "Merge SPF mechanisms into a single valid v=spf1 record.",
                ],
                validation_steps=[
                    "Query the domain TXT records and confirm exactly one v=spf1 record.",
                ],
                evidence_path=evidence_path,
                collected_at=collected_at,
                basis="direct_system_evidence",
            )
        )

    if not dmarc_records:
        findings.append(
            _email_finding(
                finding_id="BASIC-EMAIL-003",
                title="DMARC record not confirmed",
                severity="medium",
                confidence=confidence_for_basis("direct_system_evidence"),
                domain=domain,
                evidence_summary="DNS TXT lookup did not confirm a v=DMARC1 record at _dmarc.",
                why_it_matters="DMARC gives receiving mail systems policy direction for spoofed mail.",
                likely_business_impact="Spoofed email is more likely to reach clients, suppliers, and staff.",
                remediation_steps=[
                    "Publish a DMARC record starting at p=none for monitoring.",
                    "Move toward quarantine or reject after validating legitimate mail flows.",
                ],
                validation_steps=[
                    "Query _dmarc.<domain> and confirm a valid v=DMARC1 policy.",
                ],
                evidence_path=evidence_path,
                collected_at=collected_at,
                basis="direct_system_evidence",
            )
        )
    elif all("p=none" in record.lower().replace(" ", "") for record in dmarc_records):
        findings.append(
            _email_finding(
                finding_id="BASIC-EMAIL-004",
                title="DMARC policy is monitoring-only",
                severity="low",
                confidence=confidence_for_basis("direct_system_evidence"),
                domain=domain,
                evidence_summary="DMARC record exists but policy is p=none.",
                why_it_matters="Monitoring-only DMARC does not instruct receivers to quarantine or reject spoofed mail.",
                likely_business_impact="Spoofed email may still be delivered even when DMARC detects failure.",
                remediation_steps=[
                    "Use DMARC reporting to validate legitimate mail sources.",
                    "Move to quarantine or reject when operationally safe.",
                ],
                validation_steps=[
                    "Query _dmarc.<domain> and confirm policy is quarantine or reject when approved.",
                ],
                evidence_path=evidence_path,
                collected_at=collected_at,
                basis="direct_system_evidence",
            )
        )

    selectors = evidence.get("dkim_selectors_configured", [])
    if not selectors:
        findings.append(
            _email_finding(
                finding_id="BASIC-EMAIL-005",
                title="DKIM not assessed because selectors were not configured",
                severity="info",
                confidence=confidence_for_basis("inferred_partial"),
                domain=domain,
                evidence_summary="No DKIM selectors were provided, so DKIM DNS records were not tested.",
                why_it_matters="DKIM cannot be confirmed without knowing the active selector names.",
                likely_business_impact="The assessment cannot confirm or refute DKIM posture from DNS alone.",
                remediation_steps=[
                    "Identify active DKIM selectors from the mail platform.",
                    "Add selectors to config and rerun the DNS check.",
                ],
                validation_steps=[
                    "Query selector._domainkey.<domain> for each active selector.",
                ],
                evidence_path=evidence_path,
                collected_at=collected_at,
                basis="inferred_partial",
            )
        )
    elif not any(dkim_records.values()):
        findings.append(
            _email_finding(
                finding_id="BASIC-EMAIL-006",
                title="DKIM record not confirmed for configured selectors",
                severity="low",
                confidence=confidence_for_basis("direct_system_evidence"),
                domain=domain,
                evidence_summary=(
                    "DNS TXT lookup did not confirm v=DKIM1 for the configured selectors: "
                    + ", ".join(str(selector) for selector in selectors)
                ),
                why_it_matters="DKIM helps prove that outbound mail was authorized by the domain owner.",
                likely_business_impact="Mail authentication failures can reduce trust and support spoofing.",
                remediation_steps=[
                    "Confirm active DKIM selectors from the mail platform.",
                    "Publish or repair DKIM TXT records for active selectors.",
                ],
                validation_steps=[
                    "Query each active selector at selector._domainkey.<domain>.",
                ],
                evidence_path=evidence_path,
                collected_at=collected_at,
                basis="direct_system_evidence",
            )
        )

    return findings


def _email_finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    confidence: str,
    domain: str,
    evidence_summary: str,
    why_it_matters: str,
    likely_business_impact: str,
    remediation_steps: list[str],
    validation_steps: list[str],
    evidence_path: str,
    collected_at: str,
    basis: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=title,
        category="Email Security",
        package="basic",
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        asset=domain,
        evidence_summary=evidence_summary,
        evidence_files=[evidence_path],
        why_it_matters=why_it_matters,
        likely_business_impact=likely_business_impact,
        remediation_steps=remediation_steps,
        validation_steps=validation_steps,
        owner_role="Email Administrator",
        effort="low",
        evidence_source_type="dns",
        evidence_collected_at=collected_at,
        raw_evidence_path=evidence_path,
        finding_basis=basis,  # type: ignore[arg-type]
    )


def _records(payload: object) -> list[str]:
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return [str(record) for record in payload["records"]]
    return []


def _records_containing(records: list[str], marker: str) -> list[str]:
    return [record for record in records if marker.lower() in record.lower()]
