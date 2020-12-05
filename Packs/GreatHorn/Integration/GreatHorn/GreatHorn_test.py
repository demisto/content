import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_gh_get_policy_command(requests_mock):
    from GreatHorn import Client, gh_get_policy_command
    mock_response = util_load_json('test_data/policy.json')

    requests_mock.get('https://api.greathorn.com/v2/policy/4018', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "policyid": "4018"
    }

    response = gh_get_policy_command(client, args)

    assert response.outputs_prefix == 'GreatHorn.Policy'
    assert response.outputs_key_field == 'id'


def test_gh_search_message_command(requests_mock):
    from GreatHorn import Client, gh_search_message_command
    mock_response = util_load_json('test_data/message.json')
    requests_mock.post('https://api.greathorn.com/v2/search/events', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "filters": '[{"eventId":["15708"]}]'
    }

    response = gh_search_message_command(client, args)

    assert response.outputs_prefix == 'GreatHorn'
    assert response.outputs_key_field == 'eventId'


def test_gh_get_message_command(requests_mock):
    from GreatHorn import Client, gh_get_message_command
    mock_response = util_load_json('test_data/message.json')
    requests_mock.post('https://api.greathorn.com/v2/search/events', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "id": "14807"
    }

    response = gh_get_message_command(client, args)

    assert response.outputs_prefix == 'GreatHorn.Message'
    assert response.outputs_key_field == 'eventId'


def test_gh_remediate_message_command(requests_mock):
    from GreatHorn import Client, gh_remediate_message_command
    mock_response = util_load_json('test_data/remediate_success.json')
    requests_mock.post('https://api.greathorn.com/v2/remediation/quarantine', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "eventId": "14807",
        "action": "quarantine"
    }

    response = gh_remediate_message_command(client, args)

    assert response.outputs_prefix == 'GreatHorn.Remediation'
    assert response.outputs_key_field == 'eventId'


def test_gh_revert_remediate_message_command(requests_mock):
    from GreatHorn import Client, gh_revert_remediate_message_command
    mock_response = util_load_json('test_data/revert_success.json')
    requests_mock.post('https://api.greathorn.com/v2/remediation/revert/quarantine', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "eventId": "14807",
        "action": "quarantinerelease"
    }

    response = gh_revert_remediate_message_command(client, args)

    assert response.outputs_prefix == 'GreatHorn.Remediation'
    assert response.outputs_key_field == 'eventId'


def test_gh_set_policy_command(requests_mock):
    from GreatHorn import Client, gh_set_policy_command
    mock_response = util_load_json('test_data/set_policy_success.json')
    requests_mock.patch('https://api.greathorn.com/v2/policy/', json=mock_response)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    args = {
        "policyid": "16567",
        "updatemethod": "patch",
        "policyjson": '{"config": ["or", ["and", {"opt": "from", "values": ["asdf@asdf.com","asdf2@asdf2.com"], "type": "regex"}]]}'  # noqa
    }

    response = gh_set_policy_command(client, args)

    assert response.outputs_prefix == 'GreatHorn.Policy'
    assert response.outputs_key_field == 'id'


def test_gh_get_phish_reports_command(requests_mock):
    from GreatHorn import Client, gh_get_phish_reports_command
    mock_response = util_load_json('test_data/phish_response.json')
    mock_response2 = util_load_json('test_data/remediate_success.json')
    requests_mock.post('https://api.greathorn.com/v2/search/events', json=mock_response)
    requests_mock.post('https://api.greathorn.com/v2/remediation/review', json=mock_response2)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    response = gh_get_phish_reports_command(client)

    assert len(response) == 1


def test_gh_get_quarantine_release_command(requests_mock):
    from GreatHorn import Client, gh_get_quarantine_release_command
    mock_response = util_load_json('test_data/release_response.json')
    mock_response2 = util_load_json('test_data/remediate_success.json')
    requests_mock.post('https://api.greathorn.com/v2/search/events', json=mock_response)
    requests_mock.post('https://api.greathorn.com/v2/remediation/review', json=mock_response2)

    client = Client(
        base_url='https://api.greathorn.com/v2',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        })

    response = gh_get_quarantine_release_command(client)

    assert len(response) == 1
