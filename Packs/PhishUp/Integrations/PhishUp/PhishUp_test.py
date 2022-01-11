import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_investigate_url_command():
    from PhishUp import Client, investigate_url_command
    base_url = "https://apiv2.phishup.co"
    client = Client(
        base_url=base_url,
        verify=False)
    args = {
        "apikey": "not"
    }
    params = {
        "Url": "https://www.paloaltonetworks.com/"
    }
    response = investigate_url_command(client, args, params)
    mock_response = util_load_json('test_data/error.json')
    assert mock_response == list(response)


def test_investigate_bulk_url_command():
    from PhishUp import Client, investigate_bulk_url_command
    base_url = "https://apiv2.phishup.co"
    client = Client(
        base_url=base_url,
        verify=False)
    args = {
        "Urls": []
    }
    params = {
        "apikey": "not"
    }
    response = investigate_bulk_url_command(client, args, params)
    mock_response = util_load_json('test_data/bulk-empty-url.json')
    assert mock_response == list(response)


def test_get_chosen_phishup_action_command():
    from PhishUp import get_chosen_phishup_action_command
    params = {
        "phishup-playbook-action": "Nothing"
    }
    result = get_chosen_phishup_action_command(params)
    assert list(result)[1]["PhishUp.Action"] == "Nothing"


def test_investigate_url_http_request(mocker):
    from PhishUp import Client
    patcher = mocker.patch("PhishUp.Client.investigate_url_http_request", return_value="Error")
    patcher.start()
    base_url = "https://apiv2.phishup.co"
    client = Client(
        base_url=base_url,
        verify=False)
    args = {
        "apikey": "not"
    }
    params = {
        "Url": "https://www.paloaltonetworks.com/"
    }
    r = client.investigate_url_http_request(client, args, params)
    assert r == "Error"


def test_investigate_bulk_url_http_request(mocker):
    from PhishUp import Client
    patcher = mocker.patch("PhishUp.Client.investigate_bulk_url_http_request", return_value="Error")
    patcher.start()
    base_url = "https://apiv2.phishup.co"
    client = Client(
        base_url=base_url,
        verify=False)
    args = {
        "apikey": "not"
    }
    params = {
        "Url": "https://www.paloaltonetworks.com/"
    }
    r = client.investigate_bulk_url_http_request(client, args, params)
    assert r == "Error"


def test_check_api_key_test_module_http_request(mocker):
    from PhishUp import Client, test_module
    patcher = mocker.patch("PhishUp.Client.check_api_key_test_module_http_request", return_value={"Status": "Success"})
    patcher.start()
    base_url = "https://apiv2.phishup.co"
    client = Client(
        base_url=base_url,
        verify=False)
    r = test_module(client)
    assert r == "ok"
