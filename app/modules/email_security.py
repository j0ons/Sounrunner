"""SPF, DKIM, and DMARC DNS checks for Basic package."""

from __future__ import annotations

import json
from dataclasses import dataclass

from app.collectors.shell import run_command
from app.core.config import EmailSecurityConfig
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
        domain = self.session.intake.domain
        if not domain:
            return ModuleResult(
                module_name=self.name,
                status="skipped",
                detail="No email domain provided. SPF/DKIM/DMARC checks skipped.",
            )

        evidence: dict[str, object] = {
            "domain": domain,
            "spf": self._txt(domain),
            "dmarc": self._txt(f"_dmarc.{domain}"),
            "dkim": {
                selector: self._txt(f"{selector}._domainkey.{domain}")
                for selector in self.config.dkim_selectors
            },
        }
        evidence_file = self.session.crypto.write_text(
            self.session.evidence_dir / "email_security_dns.json",
            json.dumps(evidence, indent=2, sort_keys=True),
        )

        findings: list[Finding] = []
        spf_records = _records_containing(evidence["spf"], "v=spf1")
        dmarc_records = _records_containing(evidence["dmarc"], "v=DMARC1")
        dkim_hits = [
            selector
            for selector, output in dict(evidence["dkim"]).items()
            if _records_containing(output, "v=DKIM1")
        ]

        if not spf_records:
            findings.append(
                Finding(
                    finding_id="BASIC-EMAIL-001",
                    title="SPF record not confirmed",
                    category="Email Security",
                    package="basic",
                    severity="medium",
                    confidence="strong",
                    asset=domain,
                    evidence_summary="No SPF TXT record was confirmed for the domain.",
                    evidence_files=[str(evidence_file)],
                    why_it_matters="Missing SPF weakens sender authentication and increases spoofing risk.",
                    likely_business_impact="Attackers can more easily impersonate the organization in phishing.",
                    remediation_steps=[
                        "Publish a valid SPF record for approved mail sources.",
                        "Keep the SPF lookup count within DNS limits.",
                    ],
                    validation_steps=[
                        "Query the domain TXT records and confirm a single valid v=spf1 record.",
                    ],
                    owner_role="Email Administrator",
                    effort="low",
                )
            )

        if not dmarc_records:
            findings.append(
                Finding(
                    finding_id="BASIC-EMAIL-002",
                    title="DMARC record not confirmed",
                    category="Email Security",
                    package="basic",
                    severity="medium",
                    confidence="strong",
                    asset=domain,
                    evidence_summary="No DMARC TXT record was confirmed for the domain.",
                    evidence_files=[str(evidence_file)],
                    why_it_matters="DMARC gives receiving mail systems policy direction for spoofed mail.",
                    likely_business_impact="Spoofed email is more likely to reach clients, suppliers, and staff.",
                    remediation_steps=[
                        "Publish a DMARC record starting at p=none for monitoring.",
                        "Move toward quarantine or reject after validating legitimate mail flows.",
                    ],
                    validation_steps=[
                        "Query _dmarc.<domain> and confirm a valid v=DMARC1 policy.",
                    ],
                    owner_role="Email Administrator",
                    effort="low",
                )
            )

        if not dkim_hits:
            findings.append(
                Finding(
                    finding_id="BASIC-EMAIL-003",
                    title="DKIM record not confirmed for configured selectors",
                    category="Email Security",
                    package="basic",
                    severity="low",
                    confidence="weak",
                    asset=domain,
                    evidence_summary=(
                        "No DKIM TXT record was confirmed for the configured selectors. "
                        "This is weak evidence unless the active selector list is complete."
                    ),
                    evidence_files=[str(evidence_file)],
                    why_it_matters="DKIM helps prove that outbound mail was authorized by the domain owner.",
                    likely_business_impact="Mail authentication failures can reduce trust and support spoofing.",
                    remediation_steps=[
                        "Identify active DKIM selectors from the mail platform.",
                        "Publish or repair DKIM TXT records for active selectors.",
                    ],
                    validation_steps=[
                        "Query each active selector at selector._domainkey.<domain>.",
                    ],
                    owner_role="Email Administrator",
                    effort="medium",
                )
            )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail=f"Checked SPF, DMARC, and {len(self.config.dkim_selectors)} DKIM selector(s).",
            findings=findings,
            evidence_files=[evidence_file],
        )

    @staticmethod
    def _txt(name: str) -> str:
        result = run_command(["nslookup", "-type=TXT", name], timeout_seconds=15)
        return "\n".join(part for part in [result.stdout, result.stderr] if part)


def _records_containing(output: object, marker: str) -> list[str]:
    text = str(output)
    return [line for line in text.splitlines() if marker.lower() in line.lower()]
