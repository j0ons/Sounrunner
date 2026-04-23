"""Failure-safe callback pipeline for summaries and encrypted bundles."""

from __future__ import annotations

import base64
import json
import logging
import smtplib
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Protocol
from urllib import error, request

from app import __version__
from app.core.config import AppConfig
from app.core.crypto import CryptoWorkspace
from app.core.models import Finding
from app.core.secrets import resolve_secret
from app.core.session import AssessmentSession, SessionManager


@dataclass(slots=True)
class CallbackAttempt:
    provider: str
    delivery_type: str
    status: str
    detail: str
    callback_id: str
    queued_path: str = ""


class CallbackProvider(Protocol):
    name: str
    delivery_type: str

    def send(self, payload: dict[str, object], bundle_path: Path) -> CallbackAttempt:
        """Send sanitized summary and/or encrypted bundle."""


class CallbackQueue:
    """File-based callback retry queue with backoff metadata."""

    def __init__(
        self,
        queue_dir: Path,
        *,
        max_retry_attempts: int = 3,
        base_retry_delay_seconds: int = 60,
        max_retry_delay_seconds: int = 3600,
    ) -> None:
        self.queue_dir = queue_dir
        self.max_retry_attempts = max_retry_attempts
        self.base_retry_delay_seconds = base_retry_delay_seconds
        self.max_retry_delay_seconds = max_retry_delay_seconds
        self.queue_dir.mkdir(parents=True, exist_ok=True)

    def enqueue(
        self,
        *,
        session: AssessmentSession | None = None,
        provider: str,
        delivery_type: str = "bundle_upload",
        payload: dict[str, object],
        bundle_path: Path,
        error_detail: str = "",
        error: str = "",
    ) -> Path:
        callback_id = str(payload.get("callback_id") or uuid.uuid4())
        attempts = 1
        effective_error = error_detail or error
        item = {
            "callback_id": callback_id,
            "session_id": session.session_id if session else "",
            "session_root": str(session.root) if session else "",
            "provider": provider,
            "delivery_type": delivery_type,
            "payload": payload,
            "bundle_path": str(bundle_path),
            "attempts": attempts,
            "queued_at": _utc_now(),
            "last_attempt_at": _utc_now(),
            "next_attempt_at": _iso_after_seconds(self._retry_delay(attempts)),
            "status": "queued" if attempts < self.max_retry_attempts else "failed",
            "last_error": effective_error,
            "history": [
                {
                    "time": _utc_now(),
                    "status": "queued" if attempts < self.max_retry_attempts else "failed",
                    "detail": effective_error,
                }
            ],
        }
        path = self.queue_dir / f"{callback_id}-{provider}-{delivery_type}.json"
        self._save(path, item)
        return path

    def inspect(self, session_id: str | None = None) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        for path in sorted(self.queue_dir.glob("*.json")):
            item = self.load(path)
            if session_id and str(item.get("session_id")) != session_id:
                continue
            items.append(
                {
                    "path": str(path),
                    "callback_id": item.get("callback_id"),
                    "session_id": item.get("session_id"),
                    "provider": item.get("provider"),
                    "delivery_type": item.get("delivery_type"),
                    "status": item.get("status"),
                    "attempts": item.get("attempts"),
                    "next_attempt_at": item.get("next_attempt_at"),
                    "last_error": item.get("last_error", ""),
                }
            )
        return items

    def pending(self) -> list[Path]:
        return sorted(self.queue_dir.glob("*.json"))

    def due_paths(self, *, force: bool = False, session_id: str | None = None) -> list[Path]:
        due: list[Path] = []
        now = datetime.now(timezone.utc)
        for path in sorted(self.queue_dir.glob("*.json")):
            item = self.load(path)
            if session_id and str(item.get("session_id")) != session_id:
                continue
            if int(item.get("attempts", 0)) >= self.max_retry_attempts and not force:
                continue
            if force:
                due.append(path)
                continue
            next_attempt = _parse_utc(str(item.get("next_attempt_at", "")))
            if next_attempt is None or next_attempt <= now:
                due.append(path)
        return due

    def load(self, path: Path) -> dict[str, object]:
        return json.loads(path.read_text(encoding="utf-8"))

    def mark_failure(self, path: Path, detail: str) -> dict[str, object]:
        item = self.load(path)
        attempts = int(item.get("attempts", 0)) + 1
        status = "failed" if attempts >= self.max_retry_attempts else "queued"
        history = list(item.get("history", []))
        history.append({"time": _utc_now(), "status": status, "detail": detail})
        item.update(
            {
                "attempts": attempts,
                "status": status,
                "last_error": detail,
                "last_attempt_at": _utc_now(),
                "next_attempt_at": _iso_after_seconds(self._retry_delay(attempts)),
                "history": history,
            }
        )
        self._save(path, item)
        return item

    def remove(self, path: Path) -> None:
        path.unlink(missing_ok=True)

    def _retry_delay(self, attempts: int) -> int:
        delay = self.base_retry_delay_seconds * max(1, 2 ** max(0, attempts - 1))
        return min(delay, self.max_retry_delay_seconds)

    @staticmethod
    def _save(path: Path, payload: dict[str, object]) -> None:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


class CallbackManager:
    """Runs optional callbacks without blocking assessment completion."""

    def __init__(self, config: AppConfig, session: AssessmentSession) -> None:
        self.config = config
        self.session = session
        queue_root = (
            Path(config.callback.queue_dir)
            if config.callback.queue_dir
            else config.workspace_root / "callback_queue"
        )
        self.queue = CallbackQueue(
            queue_root,
            max_retry_attempts=config.callback.max_retry_attempts,
            base_retry_delay_seconds=config.callback.base_retry_delay_seconds,
            max_retry_delay_seconds=config.callback.max_retry_delay_seconds,
        )
        self.logger = logging.getLogger("soun_runner")

    def run(self, package: str, findings: list[Finding], encrypted_bundle: Path) -> str:
        payload = sanitized_summary_payload(
            session=self.session,
            package=package,
            findings=findings,
            encrypted_bundle=encrypted_bundle,
        )
        payload_file = self.session.crypto.write_text(
            self.session.export_dir / "sanitized_callback_summary.json.enc",
            json.dumps(payload, indent=2, sort_keys=True),
        )
        self.logger.info("Sanitized callback summary written: %s", payload_file)

        status_payload = _default_status_payload(
            session=self.session,
            package=package,
            callback_id=str(payload["callback_id"]),
            bundle_path=encrypted_bundle,
            summary_path=payload_file,
        )

        if not self.config.callback.enabled:
            status_payload["overall_status"] = "not_configured"
            status_payload["status_message"] = "Callback pipeline not enabled."
            self._persist_status(status_payload)
            return "not_configured"

        self.retry_pending()
        providers = self._providers()
        if not providers:
            status_payload["overall_status"] = "not_configured"
            status_payload["status_message"] = "Callback enabled but no providers are configured."
            self._persist_status(status_payload)
            return "not_configured"

        for provider in providers:
            attempt = self._attempt_provider(provider, payload, encrypted_bundle)
            _apply_attempt(status_payload, attempt)

        status_payload["overall_status"] = _overall_callback_status(status_payload["deliveries"])
        status_payload["status_message"] = _status_message(status_payload["deliveries"])
        self._persist_status(status_payload)
        return str(status_payload["overall_status"])

    def retry_pending(self, *, force: bool = False, session_id: str | None = None) -> list[dict[str, object]]:
        providers = {provider.name: provider for provider in self._providers()}
        results: list[dict[str, object]] = []
        for path in self.queue.due_paths(force=force, session_id=session_id):
            item = self.queue.load(path)
            provider_name = str(item.get("provider", ""))
            provider = providers.get(provider_name)
            if not provider:
                item = self.queue.mark_failure(path, f"Provider not available: {provider_name}")
                self._update_session_status_from_queue_item(item, path=str(path))
                results.append(item)
                continue

            bundle_path = Path(str(item.get("bundle_path", "")))
            if provider.delivery_type == "bundle_upload" and not bundle_path.exists():
                item = self.queue.mark_failure(path, f"Bundle not found: {bundle_path}")
                self._update_session_status_from_queue_item(item, path=str(path))
                results.append(item)
                continue

            try:
                attempt = provider.send(dict(item["payload"]), bundle_path)
            except Exception as exc:  # noqa: BLE001 - retries must fail safely.
                item = self.queue.mark_failure(path, str(exc))
                self.logger.exception("Queued callback retry failed: %s", path.name)
                self._update_session_status_from_queue_item(item, path=str(path))
                results.append(item)
                continue

            self.queue.remove(path)
            delivered = {
                "callback_id": item.get("callback_id"),
                "session_id": item.get("session_id"),
                "provider": attempt.provider,
                "delivery_type": attempt.delivery_type,
                "status": attempt.status,
                "detail": attempt.detail,
                "attempts": item.get("attempts", 0),
            }
            self._update_session_status_from_attempt(item, attempt)
            results.append(delivered)
        return results

    def inspect_queue(self, session_id: str | None = None) -> list[dict[str, object]]:
        return self.queue.inspect(session_id=session_id)

    def resend_session(self) -> str:
        bundle_path = self.session.export_dir / "results_bundle.zip"
        if not bundle_path.exists():
            raise FileNotFoundError(f"Encrypted bundle not found for session: {bundle_path}")
        findings = self.session.database.list_findings()
        return self.run(self.session.intake.package, findings, bundle_path)

    def _attempt_provider(
        self,
        provider: CallbackProvider,
        payload: dict[str, object],
        encrypted_bundle: Path,
    ) -> CallbackAttempt:
        try:
            attempt = provider.send(payload, encrypted_bundle)
            self.logger.info(
                "Callback provider %s type=%s status=%s",
                provider.name,
                provider.delivery_type,
                attempt.status,
            )
            return attempt
        except Exception as exc:  # noqa: BLE001 - callbacks must fail safe.
            queued_path = self.queue.enqueue(
                session=self.session,
                provider=provider.name,
                delivery_type=provider.delivery_type,
                payload=payload,
                bundle_path=encrypted_bundle,
                error_detail=str(exc),
            )
            self.logger.exception("Callback provider failed and was queued: %s", provider.name)
            return CallbackAttempt(
                provider=provider.name,
                delivery_type=provider.delivery_type,
                status="queued",
                detail=str(exc),
                callback_id=str(payload["callback_id"]),
                queued_path=str(queued_path),
            )

    def _persist_status(self, payload: dict[str, object]) -> None:
        self.session.crypto.write_text(
            self.session.callback_status_path,
            json.dumps(payload, indent=2, sort_keys=True),
        )
        self.session.database.set_metadata("callback_status", payload)

    def _update_session_status_from_queue_item(self, item: dict[str, object], *, path: str) -> None:
        delivery = {
            "provider": str(item.get("provider", "")),
            "delivery_type": str(item.get("delivery_type", "")),
            "status": str(item.get("status", "queued")),
            "detail": str(item.get("last_error", "")),
            "queued_path": path,
            "last_attempt_at": str(item.get("last_attempt_at", "")),
            "next_attempt_at": str(item.get("next_attempt_at", "")),
        }
        session_root = Path(str(item.get("session_root", "")))
        if not session_root.exists():
            return
        status_payload = _read_status_payload(session_root)
        _upsert_delivery(status_payload, delivery)
        status_payload["overall_status"] = _overall_callback_status(status_payload["deliveries"])
        status_payload["status_message"] = _status_message(status_payload["deliveries"])
        _write_status_payload(session_root, status_payload)

    def _update_session_status_from_attempt(
        self,
        item: dict[str, object],
        attempt: CallbackAttempt,
    ) -> None:
        session_root = Path(str(item.get("session_root", "")))
        if not session_root.exists():
            return
        status_payload = _read_status_payload(session_root)
        _upsert_delivery(
            status_payload,
            {
                "provider": attempt.provider,
                "delivery_type": attempt.delivery_type,
                "status": attempt.status,
                "detail": attempt.detail,
                "queued_path": "",
                "last_attempt_at": _utc_now(),
                "next_attempt_at": "",
            },
        )
        status_payload["overall_status"] = _overall_callback_status(status_payload["deliveries"])
        status_payload["status_message"] = _status_message(status_payload["deliveries"])
        _write_status_payload(session_root, status_payload)

    def _providers(self) -> list[CallbackProvider]:
        providers: list[CallbackProvider] = []
        if self.config.callback.send_smtp_summary or self.config.smtp_enabled:
            providers.append(SmtpCallbackProvider(self.config))
        if self.config.callback.upload_bundle:
            if self.config.callback.https.enabled:
                providers.append(HttpsBundleProvider(self.config))
            if self.config.callback.s3.enabled:
                providers.append(S3BundleProvider(self.config))
            if self.config.callback.sftp.enabled:
                providers.append(SftpBundleProvider(self.config))
        return providers


class SmtpCallbackProvider:
    name = "smtp"
    delivery_type = "summary_email"

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def send(self, payload: dict[str, object], bundle_path: Path) -> CallbackAttempt:
        if not self.config.smtp.is_complete:
            raise ValueError("SMTP callback enabled but SMTP config is incomplete.")
        message = EmailMessage()
        message["Subject"] = f"Soun Runner summary: {payload['client_name']}"
        message["From"] = self.config.smtp.sender
        message["To"] = self.config.smtp.recipient
        message.set_content(_summary_email_body(payload, bundle_path))
        with smtplib.SMTP(self.config.smtp.host, self.config.smtp.port, timeout=20) as smtp:
            smtp.starttls()
            if self.config.smtp.username:
                password = resolve_secret(
                    env_name=self.config.smtp.password_env,
                    file_path=self.config.smtp.password_file,
                    direct_value=self.config.smtp.password,
                    description="SMTP password",
                    allow_plaintext=True,
                )
                smtp.login(self.config.smtp.username, password.value)
            smtp.send_message(message)
        return CallbackAttempt(
            provider=self.name,
            delivery_type=self.delivery_type,
            status="sent",
            detail="SMTP summary sent.",
            callback_id=str(payload["callback_id"]),
        )


class HttpsBundleProvider:
    name = "https"
    delivery_type = "bundle_upload"

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def send(self, payload: dict[str, object], bundle_path: Path) -> CallbackAttempt:
        if not self.config.callback.https.url:
            raise ValueError("HTTPS callback enabled but URL is empty.")
        token = resolve_secret(
            env_name=self.config.callback.https.token_env,
            file_path=self.config.callback.https.token_file,
            description="HTTPS callback token",
        )
        headers = {
            "Content-Type": "application/zip",
            "X-Soun-Summary": base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii"),
        }
        if token.present:
            headers["Authorization"] = f"Bearer {token.value}"
        req = request.Request(
            self.config.callback.https.url,
            data=bundle_path.read_bytes(),
            headers=headers,
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.config.callback.https.timeout_seconds) as response:
                status = response.status
        except error.HTTPError as exc:
            raise ValueError(f"HTTPS callback failed with status {exc.code}.") from exc
        if status >= 400:
            raise ValueError(f"HTTPS callback failed with status {status}.")
        return CallbackAttempt(
            provider=self.name,
            delivery_type=self.delivery_type,
            status="sent",
            detail=f"HTTPS upload status {status}.",
            callback_id=str(payload["callback_id"]),
        )


class S3BundleProvider:
    name = "s3"
    delivery_type = "bundle_upload"

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def send(self, payload: dict[str, object], bundle_path: Path) -> CallbackAttempt:
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ValueError("S3 callback requires optional dependency boto3.") from exc
        s3cfg = self.config.callback.s3
        access_key = resolve_secret(
            env_name=s3cfg.access_key_env,
            file_path=s3cfg.access_key_file,
            description="S3 access key",
        )
        secret_key = resolve_secret(
            env_name=s3cfg.secret_key_env,
            file_path=s3cfg.secret_key_file,
            description="S3 secret key",
        )
        if not s3cfg.bucket or not access_key.present or not secret_key.present:
            raise ValueError("S3 callback missing bucket or credential environment variables.")
        client = boto3.client(
            "s3",
            endpoint_url=s3cfg.endpoint_url or None,
            region_name=s3cfg.region_name,
            aws_access_key_id=access_key.value,
            aws_secret_access_key=secret_key.value,
        )
        key = f"{s3cfg.key_prefix.rstrip('/')}/{payload['callback_id']}/{bundle_path.name}"
        client.upload_file(str(bundle_path), s3cfg.bucket, key)
        return CallbackAttempt(
            provider=self.name,
            delivery_type=self.delivery_type,
            status="sent",
            detail=f"Uploaded to s3://{s3cfg.bucket}/{key}",
            callback_id=str(payload["callback_id"]),
        )


class SftpBundleProvider:
    name = "sftp"
    delivery_type = "bundle_upload"

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def send(self, payload: dict[str, object], bundle_path: Path) -> CallbackAttempt:
        try:
            import paramiko  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ValueError("SFTP callback requires optional dependency paramiko.") from exc
        sftpcfg = self.config.callback.sftp
        password = resolve_secret(
            env_name=sftpcfg.password_env,
            file_path=sftpcfg.password_file,
            description="SFTP password",
        )
        if not sftpcfg.host or not sftpcfg.username or not password.present:
            raise ValueError("SFTP callback missing host, username, or password environment variable.")
        transport = paramiko.Transport((sftpcfg.host, sftpcfg.port))
        try:
            transport.connect(username=sftpcfg.username, password=password.value)
            sftp = paramiko.SFTPClient.from_transport(transport)
            remote = f"{sftpcfg.remote_dir.rstrip('/')}/{payload['callback_id']}-{bundle_path.name}"
            sftp.put(str(bundle_path), remote)
            sftp.close()
        finally:
            transport.close()
        return CallbackAttempt(
            provider=self.name,
            delivery_type=self.delivery_type,
            status="sent",
            detail="SFTP upload sent.",
            callback_id=str(payload["callback_id"]),
        )


def sanitized_summary_payload(
    *,
    session: AssessmentSession,
    package: str,
    findings: list[Finding],
    encrypted_bundle: Path,
) -> dict[str, object]:
    counts = Counter(finding.severity for finding in findings)
    top = sorted(findings, key=lambda item: item.risk_score, reverse=True)[:5]
    return {
        "callback_id": str(uuid.uuid4()),
        "session_id": session.session_id,
        "client_name": session.intake.client_name,
        "site": session.intake.site,
        "assessment_datetime_utc": datetime.now(timezone.utc).isoformat(),
        "package": package,
        "version": __version__,
        "severity_counts": {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "info": counts.get("info", 0),
        },
        "top_findings": [
            {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "risk_score": finding.risk_score,
            }
            for finding in top
        ],
        "bundle_filename": encrypted_bundle.name,
        "callback_status": "attempting",
    }


def inspect_callback_queue(config: AppConfig, session_id: str | None = None) -> list[dict[str, object]]:
    queue = CallbackQueue(
        Path(config.callback.queue_dir) if config.callback.queue_dir else config.workspace_root / "callback_queue",
        max_retry_attempts=config.callback.max_retry_attempts,
        base_retry_delay_seconds=config.callback.base_retry_delay_seconds,
        max_retry_delay_seconds=config.callback.max_retry_delay_seconds,
    )
    return queue.inspect(session_id=session_id)


def retry_callback_queue(
    config: AppConfig,
    *,
    force: bool = False,
    session_id: str | None = None,
) -> list[dict[str, object]]:
    items = inspect_callback_queue(config, session_id=session_id)
    if not items:
        return []

    manager = SessionManager(config)
    loaded_session = None
    for item in items:
        candidate_session_id = str(item.get("session_id", ""))
        if not candidate_session_id:
            continue
        try:
            loaded_session = manager.load_session(candidate_session_id)
            break
        except FileNotFoundError:
            continue
    if loaded_session is None:
        return []
    return CallbackManager(config, loaded_session).retry_pending(force=force, session_id=session_id)


def _default_status_payload(
    *,
    session: AssessmentSession,
    package: str,
    callback_id: str,
    bundle_path: Path,
    summary_path: Path,
) -> dict[str, object]:
    existing = _read_status_payload(session.root)
    return {
        "session_id": session.session_id,
        "package": package,
        "callback_id": callback_id,
        "updated_at": _utc_now(),
        "overall_status": existing.get("overall_status", "attempting"),
        "status_message": existing.get("status_message", ""),
        "bundle_path": str(bundle_path),
        "sanitized_summary_path": str(summary_path),
        "deliveries": existing.get("deliveries", []),
    }


def _apply_attempt(payload: dict[str, object], attempt: CallbackAttempt) -> None:
    _upsert_delivery(
        payload,
        {
            "provider": attempt.provider,
            "delivery_type": attempt.delivery_type,
            "status": attempt.status,
            "detail": attempt.detail,
            "queued_path": attempt.queued_path,
            "last_attempt_at": _utc_now(),
            "next_attempt_at": "",
        },
    )


def _upsert_delivery(payload: dict[str, object], delivery: dict[str, object]) -> None:
    deliveries = list(payload.get("deliveries", []))
    target = None
    for item in deliveries:
        if (
            isinstance(item, dict)
            and item.get("provider") == delivery["provider"]
            and item.get("delivery_type") == delivery["delivery_type"]
        ):
            target = item
            break
    if target is None:
        deliveries.append(delivery)
    else:
        target.update(delivery)
    payload["deliveries"] = deliveries
    payload["updated_at"] = _utc_now()


def _overall_callback_status(deliveries: object) -> str:
    if not isinstance(deliveries, list) or not deliveries:
        return "not_configured"
    statuses = [str(item.get("status", "")) for item in deliveries if isinstance(item, dict)]
    if statuses and all(status == "sent" for status in statuses):
        return "sent"
    if any(status == "sent" for status in statuses) and any(status in {"queued", "failed"} for status in statuses):
        return "partial"
    if any(status == "queued" for status in statuses):
        return "queued"
    if any(status == "failed" for status in statuses):
        return "failed"
    return "not_configured"


def _status_message(deliveries: object) -> str:
    if not isinstance(deliveries, list) or not deliveries:
        return "No callback delivery was attempted."
    parts = []
    for item in deliveries:
        if not isinstance(item, dict):
            continue
        parts.append(
            f"{item.get('delivery_type')} via {item.get('provider')}: {item.get('status')} ({item.get('detail', '')})"
        )
    return " | ".join(parts)


def _read_status_payload(session_root: Path) -> dict[str, object]:
    path = session_root / "export" / "callback_status.json.enc"
    crypto = CryptoWorkspace(session_root)
    if not path.exists():
        return {"deliveries": []}
    return json.loads(crypto.read_text(path))


def _write_status_payload(session_root: Path, payload: dict[str, object]) -> None:
    path = session_root / "export" / "callback_status.json.enc"
    crypto = CryptoWorkspace(session_root)
    crypto.write_text(path, json.dumps(payload, indent=2, sort_keys=True))


def _summary_email_body(payload: dict[str, object], bundle_path: Path) -> str:
    counts = dict(payload["severity_counts"])  # type: ignore[arg-type]
    lines = [
        "Soun Runner sanitized assessment summary",
        f"Client/entity: {payload['client_name']}",
        f"Site/branch: {payload['site']}",
        f"Assessment UTC: {payload['assessment_datetime_utc']}",
        f"Package: {payload['package']}",
        f"Version: {payload['version']}",
        f"Critical: {counts.get('critical', 0)}",
        f"High: {counts.get('high', 0)}",
        f"Medium: {counts.get('medium', 0)}",
        f"Low: {counts.get('low', 0)}",
        f"Bundle filename: {bundle_path.name}",
        f"Callback ID: {payload['callback_id']}",
        f"Callback status: {payload['callback_status']}",
        "Top findings:",
    ]
    for finding in payload["top_findings"]:  # type: ignore[index]
        lines.append(
            f"- {finding['severity']} {finding['finding_id']}: {finding['title']}"  # type: ignore[index]
        )
    lines.append("No raw sensitive evidence is included in this email.")
    return "\n".join(lines)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso_after_seconds(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def _parse_utc(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
