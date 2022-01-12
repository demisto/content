import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_error_investigate_url_command(mocker):
    from PhishUp import Client, investigate_url_command
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
    response = investigate_url_command(client, args, params)
    mock_response = util_load_json('test_data/error.json')
    assert mock_response == list(response)


def test_success_investigate_url_command(mocker):
    from PhishUp import Client, investigate_url_command
    mock_request_response = json.load(open("test_data/investigate-success.json"))
    patcher = mocker.patch("PhishUp.Client.investigate_url_http_request",
                           return_value=mock_request_response)
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
    response = investigate_url_command(client, args, params)
    assert response[1]["Result"] in ["Clean", "Phish", "Error"]
    assert 0 <= float(response[1]["Score"]) <= 1


def test_error_investigate_bulk_url_command(mocker):
    from PhishUp import Client, investigate_bulk_url_command
    patcher = mocker.patch("PhishUp.Client.investigate_bulk_url_http_request", return_value="Error")
    patcher.start()
    base_url = "https://apiv2.phishup.co"
    client = Client(
        base_url=base_url,
        verify=False)
    args = {
        "Urls": ["https://www.paloaltonetworks.com/"]
    }
    params = {
        "apikey": "not"
    }
    response = investigate_bulk_url_command(client, args, params)
    mock_response = util_load_json('test_data/bulk-error-url.json')
    assert mock_response == list(response)


def test_success_investigate_bulk_url_command(mocker):
    from PhishUp import Client, investigate_bulk_url_command
    mock_request_response = json.load(open("test_data/bulk-investigate-success.json"))
    patcher = mocker.patch("PhishUp.Client.investigate_bulk_url_http_request", return_value=mock_request_response)
    patcher.start()
    base_url = "https://test.com/api/v1"
    client = Client(
        base_url=base_url,
        verify=False)
    args = {
        "Urls": ["https://www.paloaltonetworks.com/cortex/xsoar", "paloaltonetworks.com"]
    }
    params = {
        "apikey": "not"
    }
    response = investigate_bulk_url_command(client, args, params)
    for index, r in enumerate(response[0]["Results"]):
        assert r["IncomingUrl"] == args["Urls"][index]
        assert r["PhishUpStatus"] in ["Clean", "Phish"]
        assert r["IsRouted"] in [False, True]
    assert response[1]["PhishUp.AverageResult"] in ["Clean", "Phish"]


def test_empty_urls_list_in_investigate_bulk_url_command():
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


def test_get_chosen_delete_mail_phishup_action_command():
    from PhishUp import get_chosen_phishup_action_command
    params = {
        "phishup-playbook-action": "Delete Mail"
    }
    result = get_chosen_phishup_action_command(params)
    assert list(result)[1]["PhishUp.Action"] == "Delete Mail"


def test_get_chosen_nothing_phishup_action_command():
    from PhishUp import get_chosen_phishup_action_command
    params = {
        "phishup-playbook-action": "Nothing"
    }
    result = get_chosen_phishup_action_command(params)
    assert list(result)[1]["PhishUp.Action"] == "Nothing"


def test_get_chosen_move_to_spam_phishup_action_command():
    from PhishUp import get_chosen_phishup_action_command
    params = {
        "phishup-playbook-action": "Move to SPAM"
    }
    result = get_chosen_phishup_action_command(params)
    assert list(result)[1]["PhishUp.Action"] == "Move to SPAM"


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


def test_auth_success_test_module(mocker):
    from PhishUp import Client, test_module
    patcher = mocker.patch("PhishUp.Client.check_api_key_test_module_http_request", return_value={"Status": "Success"})
    patcher.start()
    base_url = "https://apiv2.phishup.co"
    client = Client(
        base_url=base_url,
        verify=False)
    r = test_module(client)
    assert r == "ok"


def test_auth_error_test_module(mocker):
    from PhishUp import Client, test_module
    patcher = mocker.patch("PhishUp.Client.check_api_key_test_module_http_request", return_value={"Status": "Authentication Error"})
    patcher.start()
    base_url = "https://apiv2.phishup.co"
    client = Client(
        base_url=base_url,
        verify=False)
    r = test_module(client)
    assert r == "Authentication Error"
