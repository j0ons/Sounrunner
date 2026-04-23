"""Optional sanitized SMTP summary sender."""

from __future__ import annotations

import logging
import smtplib
from collections import Counter
from email.message import EmailMessage

from app.core.config import SmtpConfig
from app.core.models import Finding
from app.core.session import AssessmentSession


class SmtpSummarySender:
    """Sends a sanitized assessment summary without evidence files or raw telemetry."""

    def __init__(self, config: SmtpConfig, session: AssessmentSession) -> None:
        self.config = config
        self.session = session

    def send(self, findings: list[Finding]) -> bool:
        logger = logging.getLogger("soun_runner")
        if not self.config.is_complete:
            logger.warning("SMTP summary skipped: incomplete SMTP configuration")
            return False

        counts = Counter(finding.severity for finding in findings)
        body = "\n".join(
            [
                "Soun Al Hosn Assessment Runner sanitized summary",
                f"Client: {self.session.intake.client_name}",
                f"Site: {self.session.intake.site}",
                f"Session: {self.session.session_id}",
                f"Total findings: {len(findings)}",
                f"Critical: {counts.get('critical', 0)}",
                f"High: {counts.get('high', 0)}",
                f"Medium: {counts.get('medium', 0)}",
                f"Low: {counts.get('low', 0)}",
                f"Info: {counts.get('info', 0)}",
                "",
                "No raw evidence or sensitive telemetry is included in this email.",
            ]
        )

        message = EmailMessage()
        message["Subject"] = f"Assessment summary: {self.session.intake.client_name}"
        message["From"] = self.config.sender
        message["To"] = self.config.recipient
        message.set_content(body)

        with smtplib.SMTP(self.config.host, self.config.port, timeout=20) as smtp:
            smtp.starttls()
            if self.config.username:
                smtp.login(self.config.username, self.config.password)
            smtp.send_message(message)
        logger.info("Sanitized SMTP summary sent")
        return True
