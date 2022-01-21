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


def test_error_investigate_url_command(requests_mock):
    from PhishUp import Client, investigate_url_command
    requests_mock.post(f'{BASE_URL}/sherlock/investigate?apikey={MOCK_APIKEY}',
                       json=util_load_json("test_data/mock_service_error.json"))
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "Url": "https://www.paloaltonetworks.com/"
    }
    with raises(Exception, match="PhishUp Response Error"):
        response = investigate_url_command(client, args, MOCK_APIKEY)


def test_success_investigate_url_command(requests_mock):
    from PhishUp import Client, investigate_url_command

    requests_mock.post(f'{BASE_URL}/sherlock/investigate?apikey={MOCK_APIKEY}',
                       json=util_load_json("test_data/investigate_url_api_response.json"))
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "Url": "https://www.paloaltonetworks.com/"
    }
    response = investigate_url_command(client, args, MOCK_APIKEY)
    assert response.__dict__ == util_load_json("test_data/investigate-success.json")


def test_error_investigate_bulk_url_command(requests_mock):
    from PhishUp import Client, investigate_bulk_url_command
    requests_mock.post(f'{BASE_URL}/sherlock/bulk?apikey={MOCK_APIKEY}',
                       json=util_load_json("test_data/mock_service_error.json"))
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "Urls": ["https://www.paloaltonetworks.com/cortex/xsoar", "paloaltonetworks.com"]
    }
    with raises(Exception, match="PhishUp Response Error"):
        response = investigate_bulk_url_command(client, args, MOCK_APIKEY)


def test_success_investigate_bulk_url_command(requests_mock):
    from PhishUp import Client, investigate_bulk_url_command
    requests_mock.post(f'{BASE_URL}/sherlock/bulk?apikey={MOCK_APIKEY}',
                       json=util_load_json("test_data/bulk_investigate_success_response.json"))
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "Urls": ["https://www.paloaltonetworks.com/cortex/xsoar", "paloaltonetworks.com"]
    }
    response = investigate_bulk_url_command(client, args, MOCK_APIKEY)
    mock_response = util_load_json('test_data/bulk_investigate_success_return.json')
    assert response.__dict__ == mock_response


def test_empty_urls_list_in_investigate_bulk_url_command():
    from PhishUp import Client, investigate_bulk_url_command
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "Urls": []
    }
    with raises(Exception, match="Empty Urls List"):
        response = investigate_bulk_url_command(client, args, MOCK_APIKEY)


def test_string_list_success_investigate_bulk_url_command(requests_mock):
    from PhishUp import Client, investigate_bulk_url_command
    requests_mock.post(f'{BASE_URL}/sherlock/bulk?apikey={MOCK_APIKEY}',
                       json=util_load_json("test_data/bulk_investigate_success_response.json"))
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "Urls": "\"https://www.paloaltonetworks.com/cortex/xsoar\", \"paloaltonetworks.com\"]"
    }
    response = investigate_bulk_url_command(client, args, MOCK_APIKEY)
    mock_response = util_load_json('test_data/bulk_investigate_success_return.json')
    assert response.__dict__ == mock_response


def test_bad_string_parsing_in_investigate_bulk_url_command():
    from PhishUp import Client, investigate_bulk_url_command
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "Urls": "[\"https://www.paloaltonetworks.com/cortex/xsoar\", \"paloaltonetworks.com\""
    }

    with raises(json.decoder.JSONDecodeError):
        response = investigate_bulk_url_command(client, args, MOCK_APIKEY)


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
    requests_mock.post(f'{BASE_URL}/sherlock/ValidateApiKey?apikey={MOCK_APIKEY}',
                       json={"Status": "Success"})
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
    requests_mock.post(f'{BASE_URL}/sherlock/ValidateApiKey?apikey={MOCK_APIKEY}',
                       json={"Status": "Authentication Error"})
    response = main()
    assert response is None
