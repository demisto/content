""" Bonusly Integration for Cortex XSOAR - Unit Tests file
"""
import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_bonusly_module(requests_mock):
    from Bonusly import Client, test_module
    mock_response = {
        "success": True,
        "result": [
            {
                "id": "111111111111111111"
            }]
    }

    requests_mock.get('https://test.com/bonuses', json=mock_response)
    test_api_key = "TESTAPIKEY"
    bearer_token = 'Bearer ' + test_api_key
    client = Client(
        base_url='https://test.com/',
        verify=False,
        headers={'Authorization': bearer_token, 'Content-Type': 'application/json'})

    resp = test_module(client)

    assert resp == "ok"


def test_bonusly_list_bonuses_command(requests_mock):
    from Bonusly import Client, bonusly_list_bonuses_command
    mock_response = {
        "success": True,
        "result": [
            {
                "id": "111111111111111111"
            }]
    }

    requests_mock.get('https://test.com/bonuses', json=mock_response)
    test_api_key = "TESTAPIKEY"
    bearer_token = 'Bearer ' + test_api_key
    client = Client(
        base_url='https://test.com/',
        verify=False,
        headers={'Authorization': bearer_token, 'Content-Type': 'application/json'})

    url_params = {'limit': 20}
    _, outputs, raw_results = bonusly_list_bonuses_command(client, url_params)

    assert raw_results['success'] == mock_response['success']


def test_bonusly_get_bonus_command(requests_mock):
    from Bonusly import Client, bonusly_get_bonus_command
    mock_response = {'success': 'true'}
    requests_mock.get('https://test.com/bonuses/111111111111111111', json=mock_response)
    test_api_key = "TESTAPIKEY"
    bearer_token = 'Bearer ' + test_api_key
    client = Client(
        base_url='https://test.com/',
        verify=False,
        headers={'Authorization': bearer_token, 'Content-Type': 'application/json'})
    url_params = {'id': '111111111111111111'}
    _, outputs, raw_results = bonusly_get_bonus_command(client, url_params)

    assert raw_results['success'] == mock_response['success']


def test_bonusly_create_bonus_command(requests_mock):
    from Bonusly import Client, bonusly_create_bonus_command
    mock_response = {
        "success": True,
        "result": {}
    }
    requests_mock.post('https://test.com/bonuses', json=mock_response)
    test_api_key = "TESTAPIKEY"
    bearer_token = 'Bearer ' + test_api_key
    client = Client(
        base_url='https://test.com/',
        verify=False,
        headers={'Authorization': bearer_token, 'Content-Type': 'application/json'})
    url_params = {'giver_email': 'test@test.com', 'reason': '#collaboration works wonders'}
    _, outputs, raw_results = bonusly_create_bonus_command(client, url_params)

    assert raw_results['success'] == mock_response['success']


def test_bonusly_update_bonus_command(requests_mock):
    from Bonusly import Client, bonusly_update_bonus_command
    mock_response = {
        "success": True,
        "result":
            {
                "id": "111111111111111111"
            }
    }
    requests_mock.put('https://test.com/bonuses/111111111111111111', json=mock_response)
    test_api_key = "TESTAPIKEY"
    bearer_token = 'Bearer ' + test_api_key
    client = Client(
        base_url='https://test.com/',
        verify=False,
        headers={'Authorization': bearer_token, 'Content-Type': 'application/json'})
    url_params = {'id': '111111111111111111', 'reason': '#collaboration works wonders'}
    _, outputs, raw_results = bonusly_update_bonus_command(client, url_params)

    assert raw_results['success'] == mock_response['success']


def test_bonusly_delete_bonus_command(requests_mock):
    from Bonusly import Client, bonusly_delete_bonus_command
    mock_response = {
        "success": True,
        "message": "Delete example"
    }
    requests_mock.delete('https://test.com/bonuses/111111111111111111', json=mock_response)
    test_api_key = "TESTAPIKEY"
    bearer_token = 'Bearer ' + test_api_key
    client = Client(
        base_url='https://test.com/',
        verify=False,
        headers={'Authorization': bearer_token, 'Content-Type': 'application/json'})
    url_params = {'id': '111111111111111111', 'reason': '#collaboration works wonders'}
    _, outputs, raw_results = bonusly_delete_bonus_command(client, url_params)

    assert raw_results == mock_response
