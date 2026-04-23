from __future__ import annotations

import pytest

from app.collectors.windows_native import WindowsCommandEvidence, WindowsEvidence
from app.collectors.windows_remote import _categorize_remote_failure


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("Access is denied.", "access_denied"),
        ("The WinRM client cannot process the request because the name could not be resolved.", "dns_resolution"),
        ("Operation timed out while connecting to the host.", "timeout"),
        ("The firewall blocked the remote management request.", "firewall_blocked"),
        ("WinRM cannot complete the operation. Verify the service is running.", "winrm_unavailable"),
    ],
)
def test_remote_failure_categorization_maps_common_operator_blockers(
    stderr: str,
    expected: str,
) -> None:
    evidence = WindowsEvidence(
        supported=True,
        collected_at="2026-01-01T00:00:00+00:00",
        sections={
            "sample": WindowsCommandEvidence(
                name="sample",
                command="test",
                returncode=1,
                stdout="",
                stderr=stderr,
            )
        },
    )

    category, _hint = _categorize_remote_failure(evidence)

    assert category == expected
