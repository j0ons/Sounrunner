from app.modules.incident_readiness import incident_readiness_score, incident_prompts


def test_incident_readiness_score_rewards_logging_visibility() -> None:
    score = incident_readiness_score(
        logging_payload={"EventLogStatus": "Running"},
        prompts=incident_prompts(),
    )

    assert score == 50
