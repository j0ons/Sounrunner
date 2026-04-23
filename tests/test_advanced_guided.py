from app.modules.advanced_guided import advanced_plan_template


def test_advanced_plan_contains_required_guided_areas() -> None:
    categories = {item["category"] for item in advanced_plan_template()}

    assert "Business Continuity" in categories
    assert "Vendor Access" in categories
    assert "Policy/SOP" in categories
