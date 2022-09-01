import json
import io
from pytest import raises


MOCK_APIKEY = "not"
MOCK_PARAMS = {
    "credentials": {
        "password": MOCK_APIKEY
    }
}

BASE_URL = "https://apiv2.phishup.co"


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_investigate_url_authentication_error(requests_mock):
    from PhishUp import Client, investigate_url_command
    requests_mock.post(f'{BASE_URL}/sherlock/investigate?apikey={MOCK_APIKEY}',
                       json=util_load_json("test_data/authentication_error.json"))
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "url": ["https://www.paloaltonetworkscom/"]
    }
    with raises(Exception, match="PhishUp"):
        investigate_url_command(client, args, MOCK_APIKEY)


def test_investigate_url_command_empty_url_list_error(requests_mock):
    from PhishUp import Client, investigate_url_command
    requests_mock.post(f'{BASE_URL}/sherlock/investigate?apikey={MOCK_APIKEY}',
                       json=util_load_json("test_data/authentication_error.json"))
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "Url": []
    }
    with raises(Exception, match="Empty URLs list"):
        investigate_url_command(client, args, MOCK_APIKEY)


def test_success_investigate_url_command(requests_mock):
    from PhishUp import Client, investigate_url_command

    requests_mock.post(f'{BASE_URL}/sherlock/investigate?apikey={MOCK_APIKEY}',
                       json=util_load_json("test_data/investigate_api_successful_response.json"))
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "url": "https://www.paloaltonetworks.com/"
    }
    response = investigate_url_command(client, args, MOCK_APIKEY)
    assert response[0].outputs == util_load_json("test_data/investigate-success-outputs.json")
    assert response[0].raw_response == util_load_json("test_data/investigate-success-raw-response.json")


def test_get_chosen_nothing_phishup_action_command():
    from PhishUp import get_chosen_phishup_action_command
    params = {
        "phishup-playbook-action": "Nothing"
    }
    result = get_chosen_phishup_action_command(params)
    assert result.__dict__["outputs"] == {"PhishUp.Action": "Nothing"}
    assert result.__dict__["raw_response"] == "Nothing"
    assert result.__dict__["readable_output"] == "Chosen Action: Nothing"


def test_auth_success_test_module(requests_mock):
    from PhishUp import Client, test_module
    requests_mock.post(f'{BASE_URL}/auth-service/ValidateApiKey?apikey={MOCK_APIKEY}',
                       json={"Status": {"Result": "Success", "Message": ""}})
    client = Client(
        base_url=BASE_URL,
        verify=False)
    r = test_module(client, apikey=MOCK_APIKEY)
    assert r == "ok"


def test_auth_error_test_module(requests_mock, mocker):
    from PhishUp import main
    patcher = mocker.patch("demistomock.command", return_value="test-module")
    patcher_mock_params = mocker.patch("demistomock.params", return_value=MOCK_PARAMS)
    patcher_mock_params.start()
    patcher.start()
    requests_mock.post(f'{BASE_URL}/auth-service/ValidateApiKey?apikey={MOCK_APIKEY}',
                       json={"Status": {"Result": "Error", "Message": "Authentication Error"}})
    response = main()
    assert response is None
