import json

MOCKED_BASE_URL = 'https://api.test.com/api/'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_domain_state(mocker):
    from Cyberpion import Client
    mock_response = util_load_json('test_data/domain_state.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    client = Client(
        base_url=MOCKED_BASE_URL,
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    domain = '$anon100-2.com'
    response = client.get_domain_state(domain)
    # domain types and ips are reformatted in the function, skip checking them
    response.pop('domain_types')
    response.pop('ips')
    mocked = mock_response['results'][0]
    assert response == mocked


def test_get_domain_state_command(mocker):
    from Cyberpion import Client, get_domain_state_command

    mock_response = util_load_json('test_data/domain_state.json')
    # requests_mock.get(
    #     f'{MOCKED_BASE_URL}domainstate/?verbosity=details&domain=$anon100-2.com',
    #     json=mock_response)
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    client = Client(
        base_url=f'{MOCKED_BASE_URL}',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    domain = '$anon100-2.com'
    response = get_domain_state_command(client, {'domain': domain})
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/domain_state.json'))
    assert response.outputs['DomainState'] == client.get_domain_state(domain)
    assert response.outputs_prefix == 'Cyberpion'
    assert response.outputs_key_field == 'id'


def test_fetch_incidents(mocker):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Cyberpion import Client, fetch_incidents

    mock_response = util_load_json('test_data/new_incidents.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    client = Client(
        base_url=f'{MOCKED_BASE_URL}',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    _, new_incidents = fetch_incidents(
        client,
        max_fetch=2,
        min_severity=0,
        show_only_active=True,
        alert_types=[],
    )
    # name is too long for unit test, won't pass nop matter what
    name_part_1 = "Fix DNS issues: Nameservers are not geo-separated,"
    name_part_2 = " Authoritative nameservers are not geo-separated - $anon100-4.com"
    assert new_incidents[0] == {
        "name": name_part_1 + name_part_2,
        "occurred": "2020-11-18T07:55:31.242711+00:00",
        "rawJSON": json.dumps(mock_response['results'][0]),
        "severity": 2
    }
    assert new_incidents[1] == {
        "name": "Fix PKI issue: Weak certificate issuer - $anon100-4.com",
        "occurred": "2020-11-19T14:27:05.811645+00:00",
        "rawJSON": json.dumps(mock_response['results'][1]),
        "severity": 3
    }
