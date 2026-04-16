from typing import Any
from CommonServerPython import DemistoException
import json
import pytest
import importlib

MD_Aether = importlib.import_module("MetaDefenderAether")


def util_load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return MD_Aether.Client(base_url="https://test.com", api_key="mockkey", proxy=False, verify=False)


APIKEY_VALIDATION_SUCCESS = {
    "accountId": "1234",
    "username": "Aniko",
    "email": "aniko@o.com",
}


@pytest.mark.parametrize("result, expected", [(APIKEY_VALIDATION_SUCCESS, "ok")])
def test_test_module_positive(mocker, client, result, expected):
    mocker.patch.object(client, "test_module", return_value=result)
    response = MD_Aether.test_module_command(client)
    assert response == expected


APIKEY_VALIDATION_FAILURE = {"detail": "Could not validate credentials"}


@pytest.mark.parametrize("result, expected", [(APIKEY_VALIDATION_FAILURE, DemistoException)])
def test_test_module_negative(mocker, client, result, expected):
    mocker.patch.object(client, "test_module", return_value=result)
    with pytest.raises(Exception) as e:
        MD_Aether.test_module_command(client)
    assert isinstance(e.value, expected)


def test_search_query_command_hash_badfile(mocker, client):
    raw_response = util_load_json("test_data/query_hash_badfile.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = MD_Aether.search_query_command(client, {})
    assert response[0].outputs["file"]["sha256"] == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].outputs["verdict"] == "malicious"


def test_search_query_command_hash_cleanfile(mocker, client):
    raw_response = util_load_json("test_data/query_hash_cleanfile.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = MD_Aether.search_query_command(client, {})

    assert response[0].outputs["file"]["sha256"] == "b280719e9f2dd010260e6a023e0d69c64fbee8b6cbb8669c722a1da8142d3325"
    assert response[0].outputs["verdict"] == "no_threat"


def test_search_query_command_url(mocker, client):
    raw_response = util_load_json("test_data/query_url_github.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = MD_Aether.search_query_command(client, {})

    assert len(response) == 10

    assert response[0].outputs["file"]["sha256"] == "09a8b930c8b79e7c313e5e741e1d59c39ae91bc1f10cdefa68b47bf77519be57"
    assert response[0].outputs["verdict"] == "no_threat"
    assert response[1].outputs["file"]["sha256"] == "5adca05a86dbcaaa1049b14b364a9ddf305e2476064e2c0590e4ebb49696fa3b"
    assert response[4].outputs["verdict"] == "suspicious"


@pytest.mark.parametrize(
    "args, outputs",
    [
        ({"limit": "-1"}, DemistoException),
        ({"limit": "100"}, DemistoException),
        ({"limit": "a"}, Exception),
        ({"page": "-1"}, DemistoException),
        ({"page": "a"}, Exception),
        ({"page_size": "1"}, DemistoException),
        ({"page_size": "a"}, Exception),
    ],
)
def test_search_query_command_argument_check(mocker, client, args, outputs):
    mocker.patch.object(client, "get_search_query", return_value={})
    with pytest.raises(Exception) as e:
        MD_Aether.search_query_command(client, args)
    assert isinstance(e.value, outputs)


def test_scan_command_url_polling_waiting(requests_mock, mocker, client):
    from CommonServerPython import ScheduledCommand

    mocker.patch.object(client, "_http_request", return_value={"flow_id": "1234"})
    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)
    mocker.patch("builtins.open", create=True)

    args = {
        "entry_id": "test_entry_id",
        "description": "test_file",
        "tags": "tag1",
        "password": "pass1234",
        "is_private": True,
    }

    response = MD_Aether.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'


def test_scan_command_url_polling(mocker, client):
    from CommonServerPython import ScheduledCommand

    args = {"url": "https://github.com/"}
    raw_response = util_load_json("test_data/scan_command_url_response.json")
    mocker.patch.object(client, "_http_request", return_value={"flow_id": "1234"})
    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)

    response = MD_Aether.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {
        "flow_id": "1234",
        "hide_polling_output": True,
        "continue_to_poll": True,
        "url": "test.com",
    }
    mocker.patch.object(client, "get_scan_result", return_value=raw_response)
    response = MD_Aether.scan_command(client, polling_args)

    assert response[0].indicator.dbot_score.indicator == "09a8b930c8b79e7c313e5e741e1d59c39ae91bc1f10cdefa68b47bf77519be57"
    assert response[0].indicator.dbot_score.score == 1
    assert response[0].indicator.dbot_score.integration_name == "MetaDefender Aether"
    assert response[0].indicator.name == "https://github.com/"
    assert response[0].indicator.sha256 == "09a8b930c8b79e7c313e5e741e1d59c39ae91bc1f10cdefa68b47bf77519be57"
    assert response[0].outputs["finalVerdict"]["threatLevel"] == 0.25
    assert len(response[0].outputs["allTags"]) == 4
    assert response[0].outputs["overallState"] == "success_partial"
    assert response[0].outputs["taskReference"]["name"] == "transform-file"
    assert response[0].outputs["file"]["name"] == "https://github.com/"
    assert response[0].outputs["file"]["hash"] == "09a8b930c8b79e7c313e5e741e1d59c39ae91bc1f10cdefa68b47bf77519be57"
    assert response[0].outputs["file"]["type"] == "other"


def test_scan_command_file_polling(mocker, client):
    from CommonServerPython import ScheduledCommand

    args = {"entry_id": "test_entry_id"}
    raw_response = util_load_json("test_data/scan_command_zip_response.json")
    mocker.patch.object(client, "post_sample", return_value={"flow_id": "1234"})
    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)

    response = MD_Aether.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {
        "flow_id": "1234",
        "hide_polling_output": True,
        "continue_to_poll": True,
        "url": "test.com",
    }
    mocker.patch.object(client, "_http_request", return_value=raw_response)
    response = MD_Aether.scan_command(client, polling_args)

    assert len(response) == 3

    assert response[0].indicator.dbot_score.indicator == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].indicator.dbot_score.score == 3
    assert response[0].indicator.dbot_score.integration_name == "MetaDefender Aether"
    assert response[0].indicator.name == "bad_file.exe"
    assert response[0].indicator.sha256 == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].outputs["finalVerdict"]["threatLevel"] == 1
    assert len(response[0].outputs["allTags"]) == 9
    assert response[0].outputs["overallState"] == "success_partial"
    assert response[0].outputs["taskReference"]["name"] == "transform-file"
    assert response[0].outputs["file"]["name"] == "bad_file.exe"
    assert response[0].outputs["file"]["hash"] == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].outputs["file"]["type"] == "pe"

    assert response[1].indicator.dbot_score.indicator == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    assert response[1].indicator.dbot_score.score == 1
    assert response[1].indicator.dbot_score.integration_name == "MetaDefender Aether"
    assert response[1].indicator.name == "munkaltatoi.docx"
    assert response[1].indicator.sha256 == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    assert response[1].outputs["finalVerdict"]["threatLevel"] == 0.25
    assert len(response[1].outputs["allTags"]) == 3
    assert response[1].outputs["overallState"] == "success"
    assert response[1].outputs["taskReference"]["name"] == "transform-file"
    assert response[1].outputs["file"]["name"] == "munkaltatoi.docx"
    assert response[1].outputs["file"]["hash"] == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    assert response[1].outputs["file"]["type"] == "ms-office"

    assert response[2].indicator.dbot_score.indicator == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    assert response[2].indicator.dbot_score.score == 1
    assert response[2].indicator.dbot_score.integration_name == "MetaDefender Aether"
    assert response[2].indicator.name == "poorguy.png"
    assert response[2].indicator.sha256 == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    assert response[2].outputs["finalVerdict"]["threatLevel"] == 0.25
    assert len(response[2].outputs["allTags"]) == 2
    assert response[2].outputs["overallState"] == "success"
    assert response[2].outputs["taskReference"]["name"] == "transform-file"
    assert response[2].outputs["file"]["name"] == "poorguy.png"
    assert response[2].outputs["file"]["hash"] == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    assert response[2].outputs["file"]["type"] == "other"


def test_scan_command_file_invalid_password(mocker, client):
    from CommonServerPython import ScheduledCommand

    args = {"entry_id": "test_entry_id"}
    raw_response = util_load_json("test_data/scan_command_zip_invalid_pass.json")
    mocker.patch.object(client, "post_sample", return_value={"flow_id": "1234"})
    mocker.patch.object(ScheduledCommand, "raise_error_if_not_supported", return_value=None)

    response = MD_Aether.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {
        "flow_id": "1234",
        "hide_polling_output": True,
        "continue_to_poll": True,
        "url": "test.com",
    }
    mocker.patch.object(client, "get_scan_result", return_value=raw_response)

    with pytest.raises(Exception) as e:
        MD_Aether.scan_command(client, polling_args)
    assert isinstance(e.value, DemistoException)


def test_password_validator():
    raw_response = util_load_json("test_data/scan_command_zip_valid_pass.json")
    is_valid = MD_Aether.is_valid_pass(raw_response)
    assert is_valid


@pytest.mark.parametrize(
    "report, DBotScore",
    [
        (
            {
                "finalVerdict": {
                    "verdict": "UNDETERMINED",
                    "threatLevel": 0,
                }
            },
            0,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "TRUSTED",
                    "threatLevel": -1,
                }
            },
            1,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "NO_THREAT_DETECTED",
                    "threatLevel": 0.25,
                }
            },
            1,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "CONFIRMED_THREAT",
                    "threatLevel": 1.0,
                }
            },
            3,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "HIGH_RISK",
                    "threatLevel": 0.75,
                }
            },
            3,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "LOW_RISK",
                    "threatLevel": 0.5,
                }
            },
            2,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "SOME_FANCY",
                    "threatLevel": "not_a_number",
                }
            },
            0,
        ),
    ],
)
def test_build_one_reputation_result(report, DBotScore):
    reputation_result = MD_Aether.build_one_reputation_result(report)
    score = reputation_result.indicator.dbot_score.score
    assert score == DBotScore
