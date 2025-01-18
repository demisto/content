from typing import Any
from CommonServerPython import DemistoException
import json
import pytest
import importlib

MD_Sandbox = importlib.import_module("MetaDefenderSandbox")


def util_load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return MD_Sandbox.Client(
        base_url="https://test.com", api_key="mockkey", proxy=False, verify=False
    )


APIKEY_VALIDATION_SUCCESS = {
    "accountId": "1234",
    "username": "Aniko",
    "email": "aniko@o.com",
}


@pytest.mark.parametrize("result, expected", [(APIKEY_VALIDATION_SUCCESS, "ok")])
def test_test_module_positive(mocker, client, result, expected):
    mocker.patch.object(client, "test_module", return_value=result)
    response = MD_Sandbox.test_module_command(client)
    assert response == expected


APIKEY_VALIDATION_FAILURE = {"detail": "Could not validate credentials"}


@pytest.mark.parametrize(
    "result, expected", [(APIKEY_VALIDATION_FAILURE, DemistoException)]
)
def test_test_module_negative(mocker, client, result, expected):
    mocker.patch.object(client, "test_module", return_value=result)
    with pytest.raises(Exception) as e:
        MD_Sandbox.test_module_command(client)
    assert isinstance(e.value, expected)


def test_search_query_command_hash_badfile(mocker, client):
    raw_response = util_load_json("test_data/query_hash_badfile.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = MD_Sandbox.search_query_command(client, {})
    assert (
        response.outputs[0]["file"]["sha256"]
        == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    )
    assert response.outputs[0]["verdict"] == "malicious"


def test_search_query_command_hash_cleanfile(mocker, client):
    raw_response = util_load_json("test_data/query_hash_cleanfile.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = MD_Sandbox.search_query_command(client, {})

    assert (
        response.outputs[0]["file"]["sha256"]
        == "a33a6ee82144b97bf75728a7ec302dd88ae2fa54389caeb8442839580b259b85"
    )
    assert response.outputs[0]["verdict"] == "informational"


def test_search_query_command_url(mocker, client):
    raw_response = util_load_json("test_data/query_url_google.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = MD_Sandbox.search_query_command(client, {})

    assert len(response.outputs) == 10

    assert (
        response.outputs[0]["file"]["sha256"]
        == "5302e0de83c841169f0543eaf5f9a2b7313d49d35d9f3ecbeed4e6b353b5a2c8"
    )
    assert response.outputs[0]["verdict"] == "informational"
    assert (
        response.outputs[1]["file"]["sha256"]
        == "3a136f9524a2a1235a8cdd1b9fb229e20a04c2788b58a58f6904e256fa1ba0c4"
    )
    assert response.outputs[1]["verdict"] == "malicious"


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
        MD_Sandbox.search_query_command(client, args)
    assert isinstance(e.value, outputs)


def test_scan_command_url_polling_waiting(requests_mock, mocker, client):
    from CommonServerPython import ScheduledCommand

    mocker.patch.object(client, "_http_request", return_value={"flow_id": "1234"})
    mocker.patch.object(
        ScheduledCommand, "raise_error_if_not_supported", return_value=None
    )
    mocker.patch("builtins.open", create=True)

    args = {
        "entry_id": "test_entry_id",
        "description": "test_file",
        "tags": "tag1",
        "password": "pass1234",
        "is_private": True,
    }

    response = MD_Sandbox.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'


def test_scan_command_url_polling(mocker, client):
    from CommonServerPython import ScheduledCommand

    args = {"url": "https://www.google.com"}
    raw_response = util_load_json("test_data/scan_command_url_response.json")
    mocker.patch.object(client, "_http_request", return_value={"flow_id": "1234"})
    mocker.patch.object(
        ScheduledCommand, "raise_error_if_not_supported", return_value=None
    )

    response = MD_Sandbox.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {
        "flow_id": "1234",
        "hide_polling_output": True,
        "continue_to_poll": True,
        "url": "test.com",
    }
    mocker.patch.object(client, "get_scan_result", return_value=raw_response)
    response = MD_Sandbox.scan_command(client, polling_args)

    assert (
        response[0].indicator.dbot_score.indicator
        == "ac6bb669e40e44a8d9f8f0c94dfc63734049dcf6219aac77f02edf94b9162c09"
    )
    assert response[0].indicator.dbot_score.score == 1
    assert (
        response[0].indicator.dbot_score.integration_name == "MetaDefender Sandbox"
    )
    assert response[0].indicator.name == "https://www.google.com"
    assert (
        response[0].indicator.sha256
        == "ac6bb669e40e44a8d9f8f0c94dfc63734049dcf6219aac77f02edf94b9162c09"
    )
    assert response[0].outputs["finalVerdict"]["verdict"] == "BENIGN"
    assert len(response[0].outputs["allTags"]) == 2
    assert response[0].outputs["overallState"] == "success_partial"
    assert response[0].outputs["taskReference"]["name"] == "transform-file"
    assert response[0].outputs["file"]["name"] == "https://www.google.com"
    assert (
        response[0].outputs["file"]["hash"]
        == "ac6bb669e40e44a8d9f8f0c94dfc63734049dcf6219aac77f02edf94b9162c09"
    )
    assert response[0].outputs["file"]["type"] == "other"


def test_scan_command_file_polling(mocker, client):
    from CommonServerPython import ScheduledCommand

    args = {"entry_id": "test_entry_id"}
    raw_response = util_load_json("test_data/scan_command_zip_response.json")
    mocker.patch.object(client, "post_sample", return_value={"flow_id": "1234"})
    mocker.patch.object(
        ScheduledCommand, "raise_error_if_not_supported", return_value=None
    )

    response = MD_Sandbox.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {
        "flow_id": "1234",
        "hide_polling_output": True,
        "continue_to_poll": True,
        "url": "test.com",
    }
    mocker.patch.object(client, "_http_request", return_value=raw_response)
    response = MD_Sandbox.scan_command(client, polling_args)

    assert len(response) == 3

    assert (
        response[0].indicator.dbot_score.indicator
        == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    )
    assert response[0].indicator.dbot_score.score == 3
    assert (
        response[0].indicator.dbot_score.integration_name == "MetaDefender Sandbox"
    )
    assert response[0].indicator.name == "bad_file.exe"
    assert (
        response[0].indicator.sha256
        == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    )
    assert response[0].outputs["finalVerdict"]["verdict"] == "MALICIOUS"
    assert len(response[0].outputs["allTags"]) == 5
    assert response[0].outputs["overallState"] == "success"
    assert response[0].outputs["taskReference"]["name"] == "transform-file"
    assert response[0].outputs["file"]["name"] == "bad_file.exe"
    assert (
        response[0].outputs["file"]["hash"]
        == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    )
    assert response[0].outputs["file"]["type"] == "pe"

    assert (
        response[1].indicator.dbot_score.indicator
        == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    )
    assert response[1].indicator.dbot_score.score == 1
    assert (
        response[1].indicator.dbot_score.integration_name == "MetaDefender Sandbox"
    )
    assert response[1].indicator.name == "contract.docx"
    assert (
        response[1].indicator.sha256
        == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    )
    assert response[1].outputs["finalVerdict"]["verdict"] == "INFORMATIONAL"
    assert len(response[1].outputs["allTags"]) == 3
    assert response[1].outputs["overallState"] == "success"
    assert response[1].outputs["taskReference"]["name"] == "transform-file"
    assert response[1].outputs["file"]["name"] == "contract.docx"
    assert (
        response[1].outputs["file"]["hash"]
        == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    )
    assert response[1].outputs["file"]["type"] == "ms-office"

    assert (
        response[2].indicator.dbot_score.indicator
        == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    )
    assert response[2].indicator.dbot_score.score == 1
    assert (
        response[2].indicator.dbot_score.integration_name == "MetaDefender Sandbox"
    )
    assert response[2].indicator.name == "poorguy.png"
    assert (
        response[2].indicator.sha256
        == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    )
    assert response[2].outputs["finalVerdict"]["verdict"] == "INFORMATIONAL"
    assert len(response[2].outputs["allTags"]) == 1
    assert response[2].outputs["overallState"] == "success"
    assert response[2].outputs["taskReference"]["name"] == "transform-file"
    assert response[2].outputs["file"]["name"] == "poorguy.png"
    assert (
        response[2].outputs["file"]["hash"]
        == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    )
    assert response[2].outputs["file"]["type"] == "other"


def test_scan_command_file_polling_no_threat(mocker, client):
    from CommonServerPython import ScheduledCommand

    args = {"entry_id": "test_entry_id"}
    raw_response = util_load_json("test_data/scan_command_file_response.json")
    mocker.patch.object(client, "post_sample", return_value={"flow_id": "1234"})
    mocker.patch.object(
        ScheduledCommand, "raise_error_if_not_supported", return_value=None
    )

    response = MD_Sandbox.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {
        "flow_id": "1234",
        "hide_polling_output": True,
        "continue_to_poll": True,
        "url": "test.com",
    }
    mocker.patch.object(client, "_http_request", return_value=raw_response)
    response = MD_Sandbox.scan_command(client, polling_args)

    assert (
        response[0].indicator.dbot_score.indicator
        == "b280719e9f2dd010260e6a023e0d69c64fbee8b6cbb8669c722a1da8142d3325"
    )
    assert response[0].indicator.dbot_score.score == 1
    assert response[0].indicator.name == "gabi_bogre.png"
    assert response[0].outputs["finalVerdict"]["verdict"] == "NO_THREAT"


def test_scan_command_file_invalid_password(mocker, client):
    from CommonServerPython import ScheduledCommand

    args = {"entry_id": "test_entry_id"}
    raw_response = util_load_json("test_data/scan_command_zip_invalid_pass.json")
    mocker.patch.object(client, "post_sample", return_value={"flow_id": "1234"})
    mocker.patch.object(
        ScheduledCommand, "raise_error_if_not_supported", return_value=None
    )

    response = MD_Sandbox.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {
        "flow_id": "1234",
        "hide_polling_output": True,
        "continue_to_poll": True,
        "url": "test.com",
    }
    mocker.patch.object(client, "get_scan_result", return_value=raw_response)

    with pytest.raises(Exception) as e:
        MD_Sandbox.scan_command(client, polling_args)
    assert isinstance(e.value, DemistoException)


def test_password_validator():
    raw_response = util_load_json("test_data/scan_command_zip_valid_pass.json")
    is_valid = MD_Sandbox.is_valid_pass(raw_response)
    assert is_valid


@pytest.mark.parametrize(
    "report, DBotScore",
    [
        (
            {
                "finalVerdict": {
                    "verdict": "UNKNOWN",
                }
            },
            0,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "BENIGN",
                }
            },
            1,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "INFORMATIONAL",
                }
            },
            1,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "MALICIOUS",
                }
            },
            3,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "LIKELY_MALICIOUS",
                }
            },
            3,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "SUSPICIOUS",
                }
            },
            2,
        ),
        (
            {
                "finalVerdict": {
                    "verdict": "SOME_FANCY",
                }
            },
            0,
        ),
    ],
)
def test_build_one_reputation_result(report, DBotScore):
    reputation_result = MD_Sandbox.build_one_reputation_result(report)
    score = reputation_result.indicator.dbot_score.score
    assert score == DBotScore
