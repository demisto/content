import json
import io

MOCK_APIKEY = "not"
MOCK_PARAMS = {
    "apikey": MOCK_APIKEY
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
    response = investigate_url_command(client, args, MOCK_PARAMS)
    mock_response = util_load_json('test_data/error.json')
    assert mock_response == list(response)


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
    response = investigate_url_command(client, args, MOCK_PARAMS)
    # json.dump(response, open("test_data/investigate-success.json", "w"))
    assert list(response) == util_load_json("test_data/investigate-success.json")


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
    response = investigate_bulk_url_command(client, args, MOCK_PARAMS)
    mock_response = util_load_json('test_data/bulk_error_url.json')
    assert mock_response == list(response)


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
    response = investigate_bulk_url_command(client, args, MOCK_PARAMS)
    mock_response = util_load_json('test_data/bulk_investigate_success_return.json')
    assert list(response) == mock_response


def test_empty_urls_list_in_investigate_bulk_url_command():
    from PhishUp import Client, investigate_bulk_url_command
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "Urls": []
    }
    response = investigate_bulk_url_command(client, args, MOCK_PARAMS)
    mock_response = util_load_json('test_data/bulk_empty_url_error.json')
    assert mock_response == list(response)


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
    response = investigate_bulk_url_command(client, args, MOCK_PARAMS)
    mock_response = util_load_json('test_data/bulk_investigate_success_return.json')
    assert list(response) == mock_response


def test_bad_string_parsing_in_investigate_bulk_url_command():
    from PhishUp import Client, investigate_bulk_url_command
    client = Client(
        base_url=BASE_URL,
        verify=False)
    args = {
        "Urls": "\"https://www.paloaltonetworks.com/cortex/xsoar\", \"paloaltonetworks.com\""
    }
    response = investigate_bulk_url_command(client, args, MOCK_PARAMS)
    mock_response = util_load_json("test_data/bulk_bad_string_parsing_error.json")
    assert mock_response == list(response)


def test_get_chosen_nothing_phishup_action_command():
    from PhishUp import get_chosen_phishup_action_command
    params = {
        "phishup-playbook-action": "Nothing"
    }
    result = get_chosen_phishup_action_command(params)
    assert list(result)[1]["PhishUp.Action"] == "Nothing"


def test_auth_success_test_module(requests_mock):
    from PhishUp import Client, test_module
    requests_mock.post(f'{BASE_URL}/sherlock/ValidateApiKey?apikey={MOCK_APIKEY}',
                       json={"Status": "Success"})
    client = Client(
        base_url=BASE_URL,
        verify=False)
    r = test_module(client, MOCK_PARAMS)
    assert r == "ok"


def test_auth_error_test_module(requests_mock, mocker):
    from PhishUp import Client, main
    patcher = mocker.patch("demistomock.command", return_value="test-module")
    patcher_mock_params = mocker.patch("demistomock.params", return_value=MOCK_PARAMS)
    patcher_mock_params.start()
    patcher.start()
    requests_mock.post(f'{BASE_URL}/sherlock/ValidateApiKey?apikey={MOCK_APIKEY}',
                       json={"Status": "Authentication Error"})
    response = main()
    assert response is None
