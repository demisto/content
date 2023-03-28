from typing import Any
from CommonServerPython import Common, DemistoException, ExecutionMetrics
import json
import pytest
import io
import importlib

OPSWAT_Filescan = importlib.import_module("OPSWATFilescan")


def util_load_json(path: str) -> Any:
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return OPSWAT_Filescan.Client(
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
    response = OPSWAT_Filescan.test_module_command(client)
    assert response == expected


APIKEY_VALIDATION_FAILURE = {"detail": "Could not validate credentials"}


@pytest.mark.parametrize(
    "result, expected", [(APIKEY_VALIDATION_FAILURE, DemistoException)]
)
def test_test_module_negative(mocker, client, result, expected):
    mocker.patch.object(client, "test_module", return_value=result)
    with pytest.raises(Exception) as e:
        response = OPSWAT_Filescan.test_module_command(client)
    assert isinstance(e.value, expected)


def test_search_query_command_hash_badfile(mocker, client):
    raw_response = util_load_json("test_data/query_hash_badfile.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = OPSWAT_Filescan.search_query_command(client, {})

    assert response[0].indicator.dbot_score.indicator == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].indicator.dbot_score.score == 3
    assert response[0].indicator.dbot_score.integration_name == "OPSWAT Filescan"
    assert response[0].indicator.name == "bad_file.exe"
    assert response[0].indicator.sha256 == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].outputs['SHA256'] == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].outputs['Verdict'] == "malicious"


def test_search_query_command_hash_cleanfile(mocker, client):
    raw_response = util_load_json("test_data/query_hash_cleanfile.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = OPSWAT_Filescan.search_query_command(client, {})

    assert response[0].indicator.dbot_score.indicator == "a33a6ee82144b97bf75728a7ec302dd88ae2fa54389caeb8442839580b259b85"
    assert response[0].indicator.dbot_score.score == 1
    assert response[0].indicator.dbot_score.integration_name == "OPSWAT Filescan"
    assert response[0].indicator.name == "e0e1a581-1c69-414f-8c50-22fa3afc34ae_1010%40e0e1a581-1c69-414f-8c50-22fa3afc34ae"
    assert response[0].indicator.sha256 == "a33a6ee82144b97bf75728a7ec302dd88ae2fa54389caeb8442839580b259b85"
    assert response[0].outputs['SHA256'] == "a33a6ee82144b97bf75728a7ec302dd88ae2fa54389caeb8442839580b259b85"
    assert response[0].outputs['Verdict'] == "informational"


def test_search_query_command_url(mocker, client):
    raw_response = util_load_json("test_data/query_url_google.json")

    mocker.patch.object(client, "get_search_query", return_value=raw_response)
    response = OPSWAT_Filescan.search_query_command(client, {})

    assert len(response) == 10 + 1  # 1-1 separately and a summarize

    assert response[0].indicator.dbot_score.indicator == "5302e0de83c841169f0543eaf5f9a2b7313d49d35d9f3ecbeed4e6b353b5a2c8"
    assert response[0].indicator.dbot_score.score == 1
    assert response[0].indicator.dbot_score.integration_name == "OPSWAT Filescan"
    assert response[0].indicator.name == "UNKNOW.EXE"
    assert response[0].indicator.sha256 == "5302e0de83c841169f0543eaf5f9a2b7313d49d35d9f3ecbeed4e6b353b5a2c8"
    assert response[0].outputs['SHA256'] == "5302e0de83c841169f0543eaf5f9a2b7313d49d35d9f3ecbeed4e6b353b5a2c8"
    assert response[0].outputs['Verdict'] == "informational"

    assert response[1].indicator.dbot_score.indicator == "3a136f9524a2a1235a8cdd1b9fb229e20a04c2788b58a58f6904e256fa1ba0c4"
    assert response[1].indicator.dbot_score.score == 3
    assert response[1].indicator.dbot_score.integration_name == "OPSWAT Filescan"
    assert response[1].indicator.name == "Snaptube_20230323.apk"
    assert response[1].indicator.sha256 == "3a136f9524a2a1235a8cdd1b9fb229e20a04c2788b58a58f6904e256fa1ba0c4"
    assert response[1].outputs['SHA256'] == "3a136f9524a2a1235a8cdd1b9fb229e20a04c2788b58a58f6904e256fa1ba0c4"
    assert response[1].outputs['Verdict'] == "malicious"


def test_scan_command_url_polling_waiting(requests_mock, mocker, client):
    from CommonServerPython import ScheduledCommand

    mocker.patch.object(client, "post_sample", return_value={"flow_id": "1234"})
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)
    mocker.patch("builtins.open", create=True)

    response = OPSWAT_Filescan.scan_command(client, {'entry_id': 'test_entry_id'})
    assert response.readable_output == 'Waiting for submission "1234" to finish...'


def test_scan_command_url_polling(mocker, client):
    import requests
    from CommonServerPython import ScheduledCommand

    args = {'url': 'https://www.google.com'}
    raw_response = util_load_json("test_data/scan_command_url_response.json")
    mocker.patch.object(client, "post_sample", return_value={"flow_id": "1234"})
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    response = OPSWAT_Filescan.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {"flow_id": "1234", "hide_polling_output": True, "continue_to_poll": True, "url": "test.com"}
    mocker.patch.object(client, "get_scan_result", return_value=raw_response)
    response = OPSWAT_Filescan.scan_command(client, polling_args)

    assert response.indicator.dbot_score.indicator == "ac6bb669e40e44a8d9f8f0c94dfc63734049dcf6219aac77f02edf94b9162c09"
    assert response.indicator.dbot_score.score == 1
    assert response.indicator.dbot_score.integration_name == "OPSWAT Filescan"
    assert response.indicator.name == "https://www.google.com"
    assert response.indicator.sha256 == "ac6bb669e40e44a8d9f8f0c94dfc63734049dcf6219aac77f02edf94b9162c09"
    assert response.outputs['finalVerdict']['verdict'] == "BENIGN"
    assert len(response.outputs['allTags']) == 2
    assert response.outputs['overallState'] == "success_partial"
    assert response.outputs['taskReference']['name'] == "transform-file"
    assert response.outputs['file']['name'] == "https://www.google.com"
    assert response.outputs['file']['hash'] == "ac6bb669e40e44a8d9f8f0c94dfc63734049dcf6219aac77f02edf94b9162c09"
    assert response.outputs['file']['type'] == "other"


def test_scan_command_file_polling(mocker, client):
    import requests
    from CommonServerPython import ScheduledCommand

    args = {'entry_id': 'test_entry_id'}
    raw_response = util_load_json("test_data/scan_command_zip_response.json")
    mocker.patch.object(client, "post_sample", return_value={"flow_id": "1234"})
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)

    response = OPSWAT_Filescan.scan_command(client, args)
    assert response.readable_output == 'Waiting for submission "1234" to finish...'

    polling_args = {"flow_id": "1234", "hide_polling_output": True, "continue_to_poll": True, "url": "test.com"}
    mocker.patch.object(client, "get_scan_result", return_value=raw_response)
    response = OPSWAT_Filescan.scan_command(client, polling_args)

    assert len(response) == 3

    assert response[0].indicator.dbot_score.indicator == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].indicator.dbot_score.score == 3
    assert response[0].indicator.dbot_score.integration_name == "OPSWAT Filescan"
    assert response[0].indicator.name == "bad_file.exe"
    assert response[0].indicator.sha256 == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].outputs['finalVerdict']['verdict'] == "MALICIOUS"
    assert len(response[0].outputs['allTags']) == 5
    assert response[0].outputs['overallState'] == "success"
    assert response[0].outputs['taskReference']['name'] == "transform-file"
    assert response[0].outputs['file']['name'] == "bad_file.exe"
    assert response[0].outputs['file']['hash'] == "834d1dbfab8330ea5f1844f6e905ed0ac19d1033ee9a9f1122ad2051c56783dc"
    assert response[0].outputs['file']['type'] == "pe"

    assert response[1].indicator.dbot_score.indicator == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    assert response[1].indicator.dbot_score.score == 1
    assert response[1].indicator.dbot_score.integration_name == "OPSWAT Filescan"
    assert response[1].indicator.name == "contract.docx"
    assert response[1].indicator.sha256 == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    assert response[1].outputs['finalVerdict']['verdict'] == "INFORMATIONAL"
    assert len(response[1].outputs['allTags']) == 3
    assert response[1].outputs['overallState'] == "success"
    assert response[1].outputs['taskReference']['name'] == "transform-file"
    assert response[1].outputs['file']['name'] == "contract.docx"
    assert response[1].outputs['file']['hash'] == "ede5221225a03b12d11df11f4babf24e9c4a55e05aff27612813dd44876a71c2"
    assert response[1].outputs['file']['type'] == "ms-office"

    assert response[2].indicator.dbot_score.indicator == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    assert response[2].indicator.dbot_score.score == 1
    assert response[2].indicator.dbot_score.integration_name == "OPSWAT Filescan"
    assert response[2].indicator.name == "poorguy.png"
    assert response[2].indicator.sha256 == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    assert response[2].outputs['finalVerdict']['verdict'] == "INFORMATIONAL"
    assert len(response[2].outputs['allTags']) == 1
    assert response[2].outputs['overallState'] == "success"
    assert response[2].outputs['taskReference']['name'] == "transform-file"
    assert response[2].outputs['file']['name'] == "poorguy.png"
    assert response[2].outputs['file']['hash'] == "2ee79f9a52e660f2322985c72c9dffefdfb5a3c302576d61b4e629d049098cb5"
    assert response[2].outputs['file']['type'] == "other"
