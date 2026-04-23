"""M365 / Entra evidence connector."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from app.core.config import M365EntraConfig
from app.core.evidence import confidence_for_basis, utc_now
from app.core.secrets import resolve_secret
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession


LEGACY_CLIENT_APPS = {
    "Exchange ActiveSync",
    "IMAP",
    "MAPI",
    "SMTP",
    "POP",
    "other clients",
}

HIGH_VALUE_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
}


class GraphApiError(RuntimeError):
    """Graph connector error with optional HTTP status."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(slots=True)
class GraphEvidenceClient:
    """Minimal read-only Microsoft Graph client using app credentials."""

    config: M365EntraConfig

    def fetch_evidence(self) -> dict[str, object]:
        token = self.access_token()
        evidence: dict[str, object] = {
            "tenant_id": self.config.tenant_id,
            "collected_at": utc_now(),
        }
        errors: list[str] = []

        def collect(name: str, fn: Any) -> None:
            try:
                evidence[name] = fn()
            except GraphApiError as exc:
                errors.append(f"{name}: {exc}")

        collect(
            "security_defaults",
            lambda: self.get_json("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", token),
        )
        collect(
            "authentication_methods_policy",
            lambda: self.get_json("/v1.0/policies/authenticationMethodsPolicy", token),
        )
        collect(
            "user_registration_details",
            lambda: self.get_json(
                "/v1.0/reports/authenticationMethods/userRegistrationDetails",
                token,
                query={"$top": str(self.config.user_registration_limit)},
            ),
        )
        collect(
            "directory_roles",
            lambda: self.get_json(
                "/v1.0/directoryRoles",
                token,
                query={"$select": "id,displayName,description"},
            ),
        )
        if "directory_roles" in evidence:
            collect(
                "privileged_role_members",
                lambda: self._privileged_role_members(token, evidence["directory_roles"]),
            )
        collect(
            "legacy_auth_signins",
            lambda: self.get_json(
                "/v1.0/auditLogs/signIns",
                token,
                query={
                    "$top": "25",
                    "$select": "createdDateTime,userPrincipalName,clientAppUsed,appDisplayName,status",
                    "$filter": f"createdDateTime ge {_lookback_timestamp(self.config.legacy_sign_in_lookback_days)}",
                },
            ),
        )
        evidence["collection_errors"] = errors
        return evidence

    def get_json(
        self,
        path: str,
        token: str,
        query: dict[str, str] | None = None,
    ) -> dict[str, object]:
        url = self._graph_url(path, query)
        req = request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise GraphApiError(
                f"Graph request failed for {path}: HTTP {exc.code} {detail}",
                status_code=exc.code,
            ) from exc
        except error.URLError as exc:
            raise GraphApiError(f"Graph request failed for {path}: {exc.reason}") from exc
        payload = json.loads(raw)
        return payload if isinstance(payload, dict) else {"value": payload}

    def access_token(self) -> str:
        client_secret = resolve_secret(
            env_name=self.config.client_secret_env,
            file_path=self.config.client_secret_file,
            description="M365 client secret",
        )
        if not self.config.tenant_id or not self.config.client_id or not client_secret.present:
            raise GraphApiError(
                "M365/Entra connector requires tenant_id, client_id, and client secret environment variable."
            )
        form = parse.urlencode(
            {
                "client_id": self.config.client_id,
                "client_secret": client_secret.value,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            }
        ).encode("utf-8")
        req = request.Request(
            f"https://{self.config.authority_host}/{self.config.tenant_id}/oauth2/v2.0/token",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise GraphApiError(
                f"Graph authentication failed: HTTP {exc.code} {detail}",
                status_code=exc.code,
            ) from exc
        except error.URLError as exc:
            raise GraphApiError(f"Graph authentication failed: {exc.reason}") from exc
        token = str(payload.get("access_token", ""))
        if not token:
            raise GraphApiError("Graph authentication returned no access token.")
        return token

    def _graph_url(self, path: str, query: dict[str, str] | None) -> str:
        base = self.config.graph_base_url.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        if not query:
            return base + path
        return base + path + "?" + parse.urlencode(query)

    def _privileged_role_members(
        self,
        token: str,
        directory_roles: object,
    ) -> list[dict[str, object]]:
        role_items = []
        if isinstance(directory_roles, dict):
            role_items = directory_roles.get("value", [])
        if not isinstance(role_items, list):
            return []
        privileged: list[dict[str, object]] = []
        for role in role_items:
            if not isinstance(role, dict):
                continue
            display_name = str(role.get("displayName", ""))
            if display_name not in HIGH_VALUE_ROLES:
                continue
            role_id = str(role.get("id", ""))
            if not role_id:
                continue
            members = self.get_json(
                f"/v1.0/directoryRoles/{role_id}/members",
                token,
                query={"$select": "id,displayName,userPrincipalName"},
            )
            privileged.append(
                {
                    "role_id": role_id,
                    "display_name": display_name,
                    "members": members.get("value", []) if isinstance(members, dict) else [],
                }
            )
        return privileged


@dataclass(slots=True)
class M365EntraModule:
    session: AssessmentSession
    config: M365EntraConfig

    name: str = "m365_entra"

    def run(self) -> ModuleResult:
        if not self.config.enabled:
            return ModuleResult(
                module_name=self.name,
                status="skipped",
                detail="M365/Entra connector disabled.",
            )

        if self._configured_for_graph():
            return self._run_graph_collection()
        if self.config.evidence_json_path:
            return self._run_import_fallback()
        return ModuleResult(
            module_name=self.name,
            status="skipped",
            detail=(
                "M365/Entra connector enabled but no Graph app settings were provided. "
                "Configure tenant_id, client_id, and client secret environment variable."
            ),
        )

    def _run_graph_collection(self) -> ModuleResult:
        client = GraphEvidenceClient(self.config)
        collected_at = utc_now()
        payload: dict[str, object] = {
            "source": "graph_api",
            "tenant_id": self.config.tenant_id,
            "required_application_permissions": [
                "AuditLog.Read.All",
                "Policy.Read.All",
                "Policy.Read.AuthenticationMethod",
                "RoleManagement.Read.Directory",
            ],
            "notes": [
                "Authentication methods registration and sign-in evidence require appropriate Microsoft Graph application permissions.",
                "Sign-in log availability may depend on Microsoft Entra licensing and retention.",
            ],
        }
        try:
            payload["evidence"] = client.fetch_evidence()
        except GraphApiError as exc:
            payload["errors"] = [str(exc)]
            evidence_file = self.session.crypto.write_text(
                self.session.evidence_dir / "m365_entra_evidence.json.enc",
                json.dumps(payload, indent=2, sort_keys=True),
            )
            return ModuleResult(
                module_name=self.name,
                status="partial",
                detail=f"M365/Entra Graph collection failed cleanly: {exc}",
                evidence_files=[evidence_file],
            )

        evidence = payload.get("evidence", {})
        collection_errors = []
        if isinstance(evidence, dict):
            collection_errors = [
                str(item) for item in evidence.get("collection_errors", [])
                if isinstance(item, str)
            ]
        findings = self._normalize_findings(evidence, collected_at)
        payload["finding_count"] = len(findings)
        payload["errors"] = collection_errors
        evidence_file = self.session.crypto.write_text(
            self.session.evidence_dir / "m365_entra_evidence.json.enc",
            json.dumps(payload, indent=2, sort_keys=True),
        )
        for finding in findings:
            finding.evidence_files = [str(evidence_file)]
            finding.raw_evidence_path = str(evidence_file)
        return ModuleResult(
            module_name=self.name,
            status="partial" if collection_errors else "complete",
            detail=(
                "Collected M365/Entra posture evidence via Microsoft Graph."
                if not collection_errors
                else "Collected partial M365/Entra posture evidence via Microsoft Graph."
            ),
            findings=findings,
            evidence_files=[evidence_file],
        )

    def _run_import_fallback(self) -> ModuleResult:
        source = Path(self.config.evidence_json_path)
        if not source.exists():
            return ModuleResult(
                module_name=self.name,
                status="partial",
                detail=f"M365/Entra fallback evidence file not found: {source}",
            )
        payload = json.loads(source.read_text(encoding="utf-8"))
        evidence_file = self.session.crypto.write_text(
            self.session.evidence_dir / "m365_entra_evidence.json.enc",
            json.dumps({"source": "import_fallback", "evidence": payload}, indent=2, sort_keys=True),
        )
        findings = self._normalize_import_fallback(payload, str(evidence_file))
        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail="Imported M365/Entra fallback evidence JSON.",
            findings=findings,
            evidence_files=[evidence_file],
        )

    def _normalize_findings(
        self,
        evidence: object,
        collected_at: str,
    ) -> list[Finding]:
        if not isinstance(evidence, dict):
            return []

        findings: list[Finding] = []
        security_defaults = evidence.get("security_defaults", {})
        if isinstance(security_defaults, dict) and security_defaults.get("isEnabled") is False:
            findings.append(
                self._finding(
                    finding_id="STANDARD-M365-001",
                    title="Microsoft Entra security defaults are disabled",
                    severity="high",
                    evidence_summary="identitySecurityDefaultsEnforcementPolicy returned isEnabled=false.",
                    why_it_matters="Security defaults provide a baseline layer of identity protection for administrators and users.",
                    impact="Weak tenant baseline controls increase risk of account takeover and password spray success.",
                    remediation=["Enable security defaults or document stronger tenant-wide equivalent controls."],
                    validation=["Query identitySecurityDefaultsEnforcementPolicy and confirm isEnabled=true or equivalent controls are enforced."],
                    collected_at=collected_at,
                )
            )

        auth_policy = evidence.get("authentication_methods_policy", {})
        campaign_state = _registration_campaign_state(auth_policy)
        if campaign_state == "disabled":
            findings.append(
                self._finding(
                    finding_id="STANDARD-M365-002",
                    title="Authentication methods registration campaign is disabled",
                    severity="medium",
                    evidence_summary="authenticationMethodsPolicy registration campaign state is disabled.",
                    why_it_matters="A disabled registration campaign weakens tenant-wide MFA registration enforcement.",
                    impact="Users may remain unregistered for strong authentication methods for longer than intended.",
                    remediation=["Enable and scope the authentication methods registration campaign for approved user populations."],
                    validation=["Review authenticationMethodsPolicy registrationEnforcement settings and confirm campaign state is enabled."],
                    collected_at=collected_at,
                )
            )

        registration = evidence.get("user_registration_details", {})
        if isinstance(registration, dict):
            users = registration.get("value", [])
            if isinstance(users, list):
                member_users = [
                    user for user in users
                    if isinstance(user, dict) and str(user.get("userType", "")).lower() == "member"
                ]
                without_mfa = [
                    str(user.get("userPrincipalName", ""))
                    for user in member_users
                    if not bool(user.get("isMfaRegistered"))
                ]
                if without_mfa:
                    findings.append(
                        self._finding(
                            finding_id="STANDARD-M365-003",
                            title="Member users without MFA registration were observed",
                            severity="high",
                            evidence_summary=(
                                f"userRegistrationDetails returned {len(without_mfa)} non-MFA-registered member user(s) "
                                f"within the retrieved sample. Examples: {', '.join(without_mfa[:5])}"
                            ),
                            why_it_matters="Unregistered users are weaker targets for account takeover and phishing-resistant control adoption.",
                            impact="A compromised cloud account may expose mail, files, and administrative workflows.",
                            remediation=["Require MFA registration for member users and track completion against tenant policy."],
                            validation=["Re-run userRegistrationDetails and confirm the sampled member users are MFA-registered."],
                            collected_at=collected_at,
                        )
                    )

        legacy = evidence.get("legacy_auth_signins", {})
        if isinstance(legacy, dict):
            signins = legacy.get("value", [])
            legacy_events = [
                item for item in signins
                if isinstance(item, dict) and str(item.get("clientAppUsed", "")) in LEGACY_CLIENT_APPS
            ]
            if legacy_events:
                examples = [
                    f"{item.get('userPrincipalName', 'unknown')} via {item.get('clientAppUsed', 'unknown')}"
                    for item in legacy_events[:5]
                ]
                findings.append(
                    self._finding(
                        finding_id="STANDARD-M365-004",
                        title="Legacy authentication sign-ins were observed",
                        severity="high",
                        evidence_summary=(
                            f"Recent sign-in evidence contains {len(legacy_events)} legacy-auth event(s). "
                            f"Examples: {', '.join(examples)}"
                        ),
                        why_it_matters="Legacy authentication bypasses many modern identity protections and is a common account takeover path.",
                        impact="Attackers can target weaker protocols to bypass stronger cloud authentication controls.",
                        remediation=["Block legacy authentication protocols and validate application exceptions explicitly."],
                        validation=["Query recent sign-in logs and confirm no legacy clientAppUsed values remain in the sampled window."],
                        collected_at=collected_at,
                    )
                )

        privileged = evidence.get("privileged_role_members", [])
        if isinstance(privileged, list):
            role_counts = {
                str(item.get("display_name", "")): len(item.get("members", []))
                for item in privileged
                if isinstance(item, dict)
            }
            total_privileged = sum(role_counts.values())
            if any(count > 4 for count in role_counts.values()) or total_privileged > 8:
                findings.append(
                    self._finding(
                        finding_id="STANDARD-M365-005",
                        title="High-value Entra privileged role membership appears broad",
                        severity="medium",
                        evidence_summary="Privileged role member counts: " + ", ".join(
                            f"{name}={count}" for name, count in role_counts.items()
                        ),
                        why_it_matters="Broad privileged role assignment expands the tenant blast radius of any account compromise.",
                        impact="A compromised privileged identity can expose cloud administration, mail, and security tooling.",
                        remediation=["Reduce standing membership in high-value Entra roles and enforce named, reviewed role assignments."],
                        validation=["Review privileged role assignment counts and confirm they align with approved role ownership."],
                        collected_at=collected_at,
                    )
                )

        return findings

    def _normalize_import_fallback(
        self,
        payload: dict[str, object],
        evidence_path: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        collected_at = utc_now()
        if int(payload.get("users_without_mfa", 0)) > 0:
            findings.append(
                self._finding(
                    finding_id="STANDARD-M365-IMPORT-001",
                    title="Imported M365 evidence reports users without MFA",
                    severity="high",
                    evidence_summary=f"Imported evidence reports users_without_mfa={payload.get('users_without_mfa')}.",
                    why_it_matters="Cloud identity remains a primary account takeover target.",
                    impact="Unprotected cloud accounts can expose mail and tenant administration.",
                    remediation=["Validate the imported evidence and require MFA registration."],
                    validation=["Re-import updated evidence and confirm the count reaches zero."],
                    collected_at=collected_at,
                    evidence_path=evidence_path,
                )
            )
        return findings

    def _configured_for_graph(self) -> bool:
        secret = resolve_secret(
            env_name=self.config.client_secret_env,
            file_path=self.config.client_secret_file,
            description="M365 client secret",
        )
        return bool(self.config.tenant_id and self.config.client_id and secret.present)

    def _finding(
        self,
        *,
        finding_id: str,
        title: str,
        severity: str,
        evidence_summary: str,
        why_it_matters: str,
        impact: str,
        remediation: list[str],
        validation: list[str],
        collected_at: str,
        evidence_path: str = "",
    ) -> Finding:
        return Finding(
            finding_id=finding_id,
            title=title,
            category="M365/Entra",
            package="standard",
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence_for_basis("direct_system_evidence"),
            asset=self.config.tenant_id or "m365 tenant",
            evidence_summary=evidence_summary,
            evidence_files=[evidence_path] if evidence_path else [],
            why_it_matters=why_it_matters,
            likely_business_impact=impact,
            remediation_steps=remediation,
            validation_steps=validation,
            owner_role="Cloud Identity Administrator",
            effort="medium",
            evidence_source_type="m365_entra",
            evidence_collected_at=collected_at,
            raw_evidence_path=evidence_path,
            finding_basis="direct_system_evidence",
        )


def _registration_campaign_state(auth_policy: object) -> str:
    if not isinstance(auth_policy, dict):
        return ""
    registration = auth_policy.get("registrationEnforcement", {})
    if not isinstance(registration, dict):
        return ""
    campaign = registration.get("authenticationMethodsRegistrationCampaign", {})
    if not isinstance(campaign, dict):
        return ""
    return str(campaign.get("state", "")).lower()


def _lookback_timestamp(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
