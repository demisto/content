import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from TypeSafeJev import (
    Client,
    choice_command,
    evaluate_command,
    list_models_command,
    noul_command,
    parse_json_argument,
    parse_state,
    score_command,
    test_module as run_test_module,
)
from CommonServerPython import DemistoException


TEST_DATA = Path(__file__).parent / "test_data"


def load_json(name: str) -> dict:
    with (TEST_DATA / name).open(encoding="utf-8") as file:
        return json.load(file)


def test_client_builds_bearer_auth_and_normalizes_url() -> None:
    client = Client("https://api.typesafe.ai/", "secret-value", verify=True, proxy=False, timeout=17)

    assert client._base_url == "https://api.typesafe.ai"
    assert client._headers["Authorization"] == "Bearer secret-value"
    assert client.timeout == 17


def test_client_evaluate_uses_system_one_endpoint(mocker) -> None:
    client = Client("https://api.typesafe.ai", "secret-value")
    request = mocker.patch.object(client, "_http_request", return_value={"answers": {}})

    result = client.evaluate("alert", {"malicious": {"type": "noul", "instructions": "Malicious?"}})

    assert result == {"answers": {}}
    request.assert_called_once_with(
        method="POST",
        url_suffix="/v1/systemone",
        json_data={
            "state": "alert",
            "model": "jev-latest",
            "questions": {"malicious": {"type": "noul", "instructions": "Malicious?"}},
        },
        resp_type="json",
        retries=3,
        status_list_to_retry=(429, 529),
        backoff_factor=1,
    )


def test_client_list_models_uses_models_endpoint(mocker) -> None:
    client = Client("https://api.typesafe.ai", "secret-value")
    request = mocker.patch.object(client, "_http_request", return_value={"models": []})

    assert client.list_models() == {"models": []}
    request.assert_called_once_with(
        method="GET",
        url_suffix="/v1/models",
        resp_type="json",
        retries=3,
        status_list_to_retry=(429, 529),
        backoff_factor=1,
    )


def test_parse_state_supports_json_and_plain_text() -> None:
    assert parse_state('{"severity":"high"}') == {"severity": "high"}
    assert parse_state("plain alert text") == "plain alert text"
    assert parse_state("123") == "123"


def test_parse_json_argument_rejects_invalid_or_wrong_type() -> None:
    with pytest.raises(DemistoException, match="must be valid JSON"):
        parse_json_argument("not-json", "questions", dict)

    with pytest.raises(DemistoException, match="must decode to dict"):
        parse_json_argument('["not", "an", "object"]', "questions", dict)


def test_generic_evaluate_command_preserves_typed_answers() -> None:
    client = Mock(model="jev-latest")
    response = load_json("evaluate_response.json")
    client.evaluate.return_value = response

    result = evaluate_command(
        client,
        {
            "state": '{"alert":"PowerShell from Word"}',
            "questions": '{"malicious":{"type":"noul","instructions":"Is this malicious?"}}',
        },
    )

    assert result.outputs == response
    client.evaluate.assert_called_once_with(
        {"alert": "PowerShell from Word"},
        {"malicious": {"type": "noul", "instructions": "Is this malicious?"}},
        "jev-latest",
    )


def test_noul_command_returns_probability() -> None:
    client = Mock(model="jev-latest")
    client.evaluate.return_value = load_json("evaluate_response.json")

    result = noul_command(client, {"state": "Suspicious command", "instructions": "Is it malicious?"})

    assert result.outputs["probability"] == 0.91


def test_noul_command_includes_optional_true_and_false_criteria() -> None:
    client = Mock(model="jev-latest")
    client.evaluate.return_value = load_json("evaluate_response.json")

    noul_command(
        client,
        {
            "state": "Suspicious command",
            "instructions": "Is it malicious?",
            "true_criteria": '{"meaning":"malicious"}',
            "false_criteria": "benign activity",
        },
    )

    question = client.evaluate.call_args.args[1]["result"]
    assert question["criteria"] == {
        "true": {"meaning": "malicious"},
        "false": "benign activity",
    }


def test_choice_requires_at_least_two_options() -> None:
    client = Mock(model="jev-latest")

    with pytest.raises(DemistoException, match="at least two"):
        choice_command(client, {"state": "alert", "instructions": "Route it", "criteria": '{"one":null}'})


def test_choice_command_returns_selected_option() -> None:
    client = Mock(model="jev-latest")
    client.evaluate.return_value = {
        "model": "jev-1.13.0",
        "answers": {
            "result": {
                "type": "choice",
                "choice": "investigate",
                "probabilities": {"investigate": 0.8, "close": 0.2},
                "confidence": 0.8,
            }
        },
        "usage": {"input_tokens": 10, "output_tokens": 2},
    }

    result = choice_command(
        client,
        {
            "state": '{"severity":"high"}',
            "instructions": "Choose the next action",
            "criteria": '{"investigate":"Needs review","close":"Benign"}',
        },
    )

    assert result.outputs["choice"] == "investigate"
    assert result.outputs["probabilities"]["investigate"] == 0.8


def test_score_requires_two_to_ten_levels() -> None:
    client = Mock(model="jev-latest")

    with pytest.raises(DemistoException, match="between two and ten"):
        score_command(client, {"state": "alert", "instructions": "Score it", "criteria": '["only one"]'})


def test_score_command_returns_score_and_legend() -> None:
    client = Mock(model="jev-latest")
    client.evaluate.return_value = {
        "model": "jev-1.13.0",
        "answers": {
            "result": {
                "type": "score",
                "score": 2,
                "legend": "high",
                "probabilities": [0.1, 0.9],
                "confidence": 0.9,
            }
        },
        "usage": {"input_tokens": 10, "output_tokens": 2},
    }

    result = score_command(
        client,
        {"state": "Suspicious PowerShell", "instructions": "Score risk", "criteria": '["low","high"]'},
    )

    assert result.outputs["score"] == 2
    assert result.outputs["legend"] == "high"


def test_list_models_command_sets_context_key() -> None:
    client = Mock()
    client.list_models.return_value = load_json("models_response.json")

    result = list_models_command(client)

    assert result.outputs_key_field == "name"
    assert result.outputs[0]["name"] == "jev-latest"


def test_test_module_checks_model_endpoint() -> None:
    client = Mock()

    assert run_test_module(client) == "ok"
    client.list_models.assert_called_once_with()
