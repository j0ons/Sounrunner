from app.collectors.windows_native import evidence_items, parse_password_policy


def test_parse_password_policy_extracts_security_values() -> None:
    output = """
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Lockout threshold:                                    Never
"""

    parsed = parse_password_policy(output)

    assert parsed["minimum password length"] == "8"
    assert parsed["maximum password age (days)"] == "Unlimited"
    assert parsed["lockout threshold"] == "Never"


def test_evidence_items_handles_object_and_array_payloads() -> None:
    assert evidence_items({"Name": "Domain Admins"}) == [{"Name": "Domain Admins"}]
    assert evidence_items({"items": [{"Name": "A"}, {"Name": "B"}]}) == [
        {"Name": "A"},
        {"Name": "B"},
    ]
