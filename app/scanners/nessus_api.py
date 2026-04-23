"""Read-only Nessus/Tenable API export foundation."""

from __future__ import annotations

import json
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from app.core.config import NessusApiConfig
from app.core.secrets import resolve_secret
from app.core.session import AssessmentSession
from app.scanners.base import ScannerResult
from app.scanners.nessus_import import parse_nessus_xml


class NessusApiError(RuntimeError):
    """Raised for Nessus API failures."""


@dataclass(slots=True)
class NessusApiClient:
    """Fetch completed Nessus exports through the vendor API."""

    session: AssessmentSession
    config: NessusApiConfig

    name: str = "nessus_api"

    def list_scans(self) -> dict[str, object]:
        return self._request_json("GET", "/scans")

    def fetch_scan_export(self) -> ScannerResult:
        if not self.config.enabled:
            return ScannerResult(
                scanner_name=self.name,
                status="skipped",
                detail="Nessus API connector disabled.",
            )
        if not self.config.base_url or not self.config.scan_id:
            return ScannerResult(
                scanner_name=self.name,
                status="skipped",
                detail="Nessus API connector requires base_url and scan_id.",
            )

        file_id = self._request_export()
        self._wait_for_export(file_id)
        raw_bytes = self._download_export(file_id)
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        evidence_path = self.session.crypto.write_text(
            self.session.evidence_dir / f"nessus_api_export_{self.config.scan_id}.nessus.enc",
            raw_text,
        )
        findings = parse_nessus_xml(raw_text, raw_evidence_path=str(evidence_path))
        return ScannerResult(
            scanner_name=self.name,
            status="complete",
            detail=f"Fetched and parsed Nessus export for scan {self.config.scan_id}.",
            findings=findings,
            raw_evidence_path=evidence_path,
        )

    def _request_export(self) -> str:
        payload = {"format": self.config.export_format}
        query = f"?history_id={parse.quote(self.config.history_id)}" if self.config.history_id else ""
        response = self._request_json(
            "POST",
            f"/scans/{self.config.scan_id}/export{query}",
            data=payload,
        )
        file_id = response.get("file") or response.get("file_id")
        if not file_id:
            raise NessusApiError("Nessus export request did not return a file identifier.")
        return str(file_id)

    def _wait_for_export(self, file_id: str) -> None:
        deadline = time.time() + self.config.timeout_seconds
        while time.time() < deadline:
            payload = self._request_json(
                "GET",
                f"/scans/{self.config.scan_id}/export/{file_id}/status",
            )
            status = str(payload.get("status", "")).lower()
            if status == "ready":
                return
            if status in {"error", "failed", "canceled"}:
                raise NessusApiError(f"Nessus export entered terminal state: {status}")
            time.sleep(5)
        raise NessusApiError("Timed out waiting for Nessus export to become ready.")

    def _download_export(self, file_id: str) -> bytes:
        return self._request_bytes(
            "GET",
            f"/scans/{self.config.scan_id}/export/{file_id}/download",
            accept="application/octet-stream",
        )

    def _request_json(
        self,
        method: str,
        path: str,
        data: dict[str, object] | None = None,
    ) -> dict[str, object]:
        raw = self._request_bytes(method, path, data=data, accept="application/json")
        payload = json.loads(raw.decode("utf-8"))
        return payload if isinstance(payload, dict) else {"value": payload}

    def _request_bytes(
        self,
        method: str,
        path: str,
        data: dict[str, object] | None = None,
        accept: str = "application/json",
    ) -> bytes:
        access_key = resolve_secret(
            env_name=self.config.access_key_env,
            file_path=self.config.access_key_file,
            description="Nessus access key",
        )
        secret_key = resolve_secret(
            env_name=self.config.secret_key_env,
            file_path=self.config.secret_key_file,
            description="Nessus secret key",
        )
        if not access_key.present or not secret_key.present:
            raise NessusApiError("Nessus API credentials are missing from environment variables.")
        url = self.config.base_url.rstrip("/") + path
        body = json.dumps(data).encode("utf-8") if data is not None else None
        req = request.Request(
            url,
            data=body,
            headers={
                "Accept": accept,
                "Content-Type": "application/json",
                "X-ApiKeys": f"accessKey={access_key.value}; secretKey={secret_key.value}",
            },
            method=method,
        )
        try:
            context = None if self.config.verify_tls else ssl._create_unverified_context()
            with request.urlopen(req, timeout=self.config.timeout_seconds, context=context) as response:
                return response.read()
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise NessusApiError(f"Nessus API {method} {path} failed: HTTP {exc.code} {detail}") from exc
        except error.URLError as exc:
            raise NessusApiError(f"Nessus API {method} {path} failed: {exc.reason}") from exc
