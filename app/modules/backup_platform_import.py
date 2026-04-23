"""Imported backup platform evidence foundation."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import AppConfig
from app.core.evidence import confidence_for_basis, utc_now
from app.core.inventory import AssetInventory
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession


SUPPORTED_BACKUP_IMPORT_FORMATS = [
    "vendor-neutral JSON with jobs array",
    "flat CSV with asset,status,last_run,last_success,repository_type,immutable,offline,restore_test",
]


@dataclass(slots=True)
class BackupPlatformImportModule:
    session: AssessmentSession
    config: AppConfig

    name: str = "backup_platform_import"

    def run(self) -> ModuleResult:
        if not self.config.backup_platform_import.enabled or not self.config.backup_platform_import.import_paths:
            return ModuleResult(
                module_name=self.name,
                status="skipped",
                detail="Backup platform import foundation disabled or no import paths configured.",
            )

        inventory = AssetInventory(self.session, self.config)
        findings: list[Finding] = []
        evidence_files: list[Path] = []
        jobs: list[dict[str, Any]] = []
        parsed_files = 0
        sources: list[dict[str, Any]] = []
        for configured_path in self.config.backup_platform_import.import_paths:
            path = Path(configured_path)
            if not path.exists():
                continue
            payload = _load_backup_payload(path)
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            evidence_path = self.session.crypto.write_text(
                self.session.evidence_dir / f"backup_platform_import_{path.name}",
                raw_text,
            )
            evidence_files.append(evidence_path)
            parsed_files += 1
            current_jobs = payload["jobs"]
            jobs.extend(current_jobs)
            sources.append({"path": str(evidence_path), "job_count": len(current_jobs)})
            findings.extend(
                _findings_from_backup_jobs(
                    session=self.session,
                    inventory=inventory,
                    jobs=current_jobs,
                    evidence_path=str(evidence_path),
                    stale_success_days=self.config.backup_platform_import.stale_success_days,
                )
            )

        summary = _backup_import_summary(jobs, sources, self.config.backup_platform_import.stale_success_days)
        self.session.database.set_metadata("backup_platform_import_summary", summary)
        if not parsed_files:
            return ModuleResult(
                module_name=self.name,
                status="partial",
                detail="Backup platform import paths were configured but no readable evidence files were found.",
            )
        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail=f"Parsed {parsed_files} backup platform evidence file(s).",
            findings=findings,
            evidence_files=evidence_files,
        )


def _load_backup_payload(path: Path) -> dict[str, list[dict[str, Any]]]:
    if path.suffix.lower() == ".json":
        loaded = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(loaded, dict):
            raise ValueError(f"Unsupported backup import JSON root in {path.name}")
        return {"jobs": _dict_items(loaded.get("jobs"))}
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            return {"jobs": [{str(key): value for key, value in row.items()} for row in reader]}
    raise ValueError(f"Unsupported backup import format: {path.name}")


def _findings_from_backup_jobs(
    *,
    session: AssessmentSession,
    inventory: AssetInventory,
    jobs: list[dict[str, Any]],
    evidence_path: str,
    stale_success_days: int,
) -> list[Finding]:
    findings: list[Finding] = []
    collected_at = utc_now()
    for job in jobs:
        asset = inventory.record_imported_asset(
            hostname=str(job.get("asset") or job.get("hostname") or "backup-job-asset"),
            ip_address=str(job.get("ip_address", "")),
            source="backup_platform_import",
            criticality_hint=str(job.get("criticality", "")).lower(),
            site_label=str(job.get("site", "")),
            business_unit=str(job.get("business_unit", "")),
        )
        inventory.attach_evidence(asset.asset_id, evidence_path, "backup_platform_import")
        status = str(job.get("status", "")).strip().lower()
        if status in {"failed", "error"}:
            findings.append(
                _finding(
                    finding_id=f"BACKUP-FAILED-{asset.asset_id}",
                    title="Backup job failure imported from backup platform evidence",
                    severity="high" if asset.criticality in {"high", "critical"} else "medium",
                    asset=asset.display_name,
                    summary=f"Imported backup evidence reported job status={status} for {asset.display_name}.",
                    why="Failed backup jobs reduce recoverability and must be validated quickly for important systems.",
                    impact="A failed backup job can leave the asset unrecoverable during ransomware or outage response.",
                    remediation=["Review the failing job and restore protection for the asset."],
                    validation=["Provide backup platform evidence of a subsequent successful job run."],
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    package=session.intake.package,
                )
            )
        last_success_age = _days_since(job.get("last_success"))
        if last_success_age is not None and last_success_age > stale_success_days:
            findings.append(
                _finding(
                    finding_id=f"BACKUP-STALE-{asset.asset_id}",
                    title="Last successful backup appears stale in imported evidence",
                    severity="high" if asset.criticality in {"high", "critical"} else "medium",
                    asset=asset.display_name,
                    summary=f"Imported backup evidence shows last successful backup {last_success_age} days old.",
                    why="Stale backups reduce the chance of meeting recovery objectives for current business data.",
                    impact="Recovery may succeed only to an unacceptable age of data.",
                    remediation=["Investigate backup coverage and resume successful backups for the asset."],
                    validation=["Provide backup platform evidence showing a recent successful backup."],
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    package=session.intake.package,
                )
            )
        if _is_false(job.get("immutable")) or _is_false(job.get("offline")):
            findings.append(
                _finding(
                    finding_id=f"BACKUP-COPY-{asset.asset_id}",
                    title="Imported backup evidence indicates immutable or offline protections are absent",
                    severity="high" if asset.criticality in {"high", "critical"} else "medium",
                    asset=asset.display_name,
                    summary=(
                        f"immutable={job.get('immutable', '')} offline={job.get('offline', '')} "
                        f"for {asset.display_name}."
                    ),
                    why="Reachable backups are at higher risk during ransomware or admin-level compromise.",
                    impact="A threat that reaches the backup platform may damage both production and recovery paths.",
                    remediation=["Implement immutable or offline backup protections for the asset or repository."],
                    validation=["Provide updated backup platform evidence showing immutable or offline copy protection."],
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    package=session.intake.package,
                )
            )
        restore_status = str(job.get("restore_test", "")).strip().lower()
        if restore_status in {"failed", "never", "not_tested"}:
            findings.append(
                _finding(
                    finding_id=f"BACKUP-RESTORE-{asset.asset_id}",
                    title="Imported backup evidence indicates restore testing is missing or failed",
                    severity="medium",
                    asset=asset.display_name,
                    summary=f"restore_test={restore_status} for {asset.display_name}.",
                    why="Backup success is not the same as restore readiness.",
                    impact="Recovery may fail when needed even if jobs report success.",
                    remediation=["Perform and document restore testing for the asset or service."],
                    validation=["Provide a backup platform or operator record of a successful restore test."],
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    package=session.intake.package,
                )
            )
    return findings


def _backup_import_summary(
    jobs: list[dict[str, Any]],
    sources: list[dict[str, Any]],
    stale_success_days: int,
) -> dict[str, Any]:
    recent_successes = sum(
        1
        for job in jobs
        if _days_since(job.get("last_success")) is not None and _days_since(job.get("last_success")) <= stale_success_days
    )
    immutable_count = sum(1 for job in jobs if _is_true(job.get("immutable")))
    offline_count = sum(1 for job in jobs if _is_true(job.get("offline")))
    restore_test_confirmed = sum(
        1 for job in jobs if str(job.get("restore_test", "")).strip().lower() in {"passed", "success", "successful"}
    )
    return {
        "sources": sources,
        "job_count": len(jobs),
        "recent_success_count": recent_successes,
        "immutable_count": immutable_count,
        "offline_count": offline_count,
        "restore_test_confirmed_count": restore_test_confirmed,
        "supported_formats": SUPPORTED_BACKUP_IMPORT_FORMATS,
        "stale_success_days": stale_success_days,
    }


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    asset: str,
    summary: str,
    why: str,
    impact: str,
    remediation: list[str],
    validation: list[str],
    evidence_path: str,
    collected_at: str,
    package: str,
) -> Finding:
    return Finding(
        finding_id=finding_id[:120],
        title=title,
        category="Backup Platform Evidence",
        package=package,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence_for_basis("imported_configuration_evidence"),
        asset=asset,
        evidence_summary=summary,
        evidence_files=[evidence_path],
        why_it_matters=why,
        likely_business_impact=impact,
        remediation_steps=remediation,
        validation_steps=validation,
        owner_role="Backup Owner",
        effort="medium",
        evidence_source_type="backup_platform_import",
        evidence_collected_at=collected_at,
        raw_evidence_path=evidence_path,
        finding_basis="imported_configuration_evidence",
    )


def _dict_items(value: object) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _days_since(value: object) -> int | None:
    parsed = _parse_date(value)
    if not parsed:
        return None
    return (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).days


def _parse_date(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y"):
        try:
            return datetime.strptime(text[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_true(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _is_false(value: object) -> bool:
    return str(value).strip().lower() in {"0", "false", "no", "n"}
