import json
import io


def util_load_json(path):
    # VS Code pytest support
    import os
    path_to_current_file = os.path.realpath(__file__)
    current_directory = os.path.dirname(path_to_current_file)
    path = os.path.join(current_directory, path)
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


BASE_URL = 'https://sepio-prime/prime/webui'
TOKEN = 'Bearer api_key'
USERNAME = 'username'
PASSWORD = 'password'


def test_sepio_query_agents(requests_mock):
    """Tests sepio-query-agents command function.

    Configures requests_mock instance to generate the appropriate
    API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    from SepioPrimeAPI import Client, sepio_query_agents_command

    #  mock api http response
    mock_signin_http_response = util_load_json('test_data/signin_http_response.json')
    requests_mock.post(
        f'{BASE_URL}/auth/signin',
        json=mock_signin_http_response)

    mock_agents_http_response = util_load_json('test_data/agents_http_response.json')
    requests_mock.get(
        f'{BASE_URL}/agents',
        json=mock_agents_http_response)

    mock_agents_query_test = util_load_json('test_data/agents_query_test.json')

    client = Client(
        base_url=f'{BASE_URL}',
        verify=False,
        headers={
            'Authentication': TOKEN
        },
        auth=(USERNAME, PASSWORD)
    )

    args = {
        'has_unapproved_peripherals': False,
        'has_vulnerable_peripherals': False,
        'has_known_attack_tools': False,
        'limit': 10
    }

    response = sepio_query_agents_command(client, args)

    assert response.outputs_prefix == 'Sepio.Agent'
    assert response.outputs_key_field == 'UUID'
    assert response.outputs == mock_agents_query_test


def test_sepio_query_global_peripherals(requests_mock):
    """Tests sepio-query-peripherals command function.

    Configures requests_mock instance to generate the appropriate
    API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    from SepioPrimeAPI import Client, sepio_query_global_peripherals_command

    #  mock api http response
    mock_signin_http_response = util_load_json('test_data/signin_http_response.json')
    requests_mock.post(
        f'{BASE_URL}/auth/signin',
        json=mock_signin_http_response)

    mock_global_peripherals_http_response = util_load_json('test_data/global_peripherals_http_response.json')
    requests_mock.get(
        f'{BASE_URL}/peripherals',
        json=mock_global_peripherals_http_response)

    mock_global_peripherals_query_test = util_load_json('test_data/global_peripherals_query_test.json')

    client = Client(
        base_url=f'{BASE_URL}',
        verify=False,
        headers={
            'Authentication': TOKEN
        },
        auth=(USERNAME, PASSWORD)
    )

    args = {
        'host_uuid': 'BFEBFBFF000806EAL1HF8C4003Z',
        'vendor_name': 'Logitech, Inc.',
        'is_unapproved_peripheral': False,
        'is_vulnerable_peripheral': False,
        'is_known_attackTool': False,
        'limit': 10
    }

    response = sepio_query_global_peripherals_command(client, args)

    assert response.outputs_prefix == 'Sepio.Peripheral((val.HostUUID == obj.HostUUID) && (val.DeviceID == obj.DeviceID))'
    assert response.outputs_key_field == ''
    assert response.outputs == mock_global_peripherals_query_test


def test_sepio_query_switches(requests_mock):
    """Tests sepio-query-switches command function.

    Configures requests_mock instance to generate the appropriate
    API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    from SepioPrimeAPI import Client, sepio_query_switches_command

    #  mock api http response
    mock_signin_http_response = util_load_json('test_data/signin_http_response.json')
    requests_mock.post(
        f'{BASE_URL}/auth/signin',
        json=mock_signin_http_response)

    mock_switches_http_response = util_load_json('test_data/switches_http_response.json')
    requests_mock.get(
        f'{BASE_URL}/switches/switches',
        json=mock_switches_http_response)

    mock_switches_query_test = util_load_json('test_data/switches_query_test.json')

    client = Client(
        base_url=f'{BASE_URL}',
        verify=False,
        headers={
            'Authentication': TOKEN
        },
        auth=(USERNAME, PASSWORD)
    )

    args = {
        'model': 'WS-C2960',
        'is_alarmed': False,
        'limit': 10
    }

    response = sepio_query_switches_command(client, args)

    assert response.outputs_prefix == 'Sepio.Switch'
    assert response.outputs_key_field == 'SwitchID'
    assert response.outputs == mock_switches_query_test


def test_sepio_query_switch_ports(requests_mock):
    """Tests sepio-query-switch-ports command function.

    Configures requests_mock instance to generate the appropriate
    API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    from SepioPrimeAPI import Client, sepio_query_switch_ports_command

    #  mock api http response
    mock_signin_http_response = util_load_json('test_data/signin_http_response.json')
    requests_mock.post(
        f'{BASE_URL}/auth/signin',
        json=mock_signin_http_response)

    mock_ports_http_response = util_load_json('test_data/ports_http_response.json')
    requests_mock.get(
        f'{BASE_URL}/switches/ports',
        json=mock_ports_http_response)

    mock_ports_query_test = util_load_json('test_data/ports_query_test.json')

    client = Client(
        base_url=f'{BASE_URL}',
        verify=False,
        headers={
            'Authentication': TOKEN
        },
        auth=(USERNAME, PASSWORD)
    )

    args = {
        'switch_ip_address': '192.168.100.25',
        'switch_name': 'sepio2960g',
        'is_alarmed': False,
        'limit': 30
    }

    response = sepio_query_switch_ports_command(client, args)

    assert response.outputs_prefix == 'Sepio.Port((val.SwitchID == obj.SwitchID) && (val.PortID == obj.PortID))'
    assert response.outputs_key_field == ''
    assert response.outputs == mock_ports_query_test


def test_sepio_query_system_events(requests_mock):
    """Tests sepio-query-system-events command function.

    Configures requests_mock instance to generate the appropriate
    API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    from SepioPrimeAPI import Client, sepio_query_system_events_command

    #  mock api http response
    mock_signin_http_response = util_load_json('test_data/signin_http_response.json')
    requests_mock.post(
        f'{BASE_URL}/auth/signin',
        json=mock_signin_http_response)

    mock_events_http_response = util_load_json('test_data/events_http_response.json')
    requests_mock.get(
        f'{BASE_URL}/events/getevents',
        json=mock_events_http_response)

    mock_events_query_test = util_load_json('test_data/events_query_test.json')

    client = Client(
        base_url=f'{BASE_URL}',
        verify=False,
        headers={
            'Authentication': TOKEN
        },
        auth=(USERNAME, PASSWORD)
    )

    args = {
        'start_datetime': '2020-03-01T14:11:06Z',
        'end_datetime': '2020-05-30T14:11:06Z',
        'min_severity': 'Notice',
        'category': ['USB', 'Network'],
        'source': 'DESKTOP-9LR722S (192.168.100.128)',
        'peripheral_type': '1,2,3',
        'from_eventid': '1',
    }

    response = sepio_query_system_events_command(client, args)

    assert response.outputs_prefix == 'Sepio.Event'
    assert response.outputs_key_field == 'EventID'
    assert response.outputs == mock_events_query_test


def test_sepio_set_agent_mode(requests_mock):
    """Tests sepio-set-agent-mode command function.

    Configures requests_mock instance to generate the appropriate
    API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    from SepioPrimeAPI import Client, sepio_set_agent_mode_command

    #  mock api http response
    mock_signin_http_response = util_load_json('test_data/signin_http_response.json')
    requests_mock.post(
        f'{BASE_URL}/auth/signin',
        json=mock_signin_http_response)

    mock_set_agent_mode_http_reponse = util_load_json('test_data/set_agent_mode_http_reponse.json')
    requests_mock.post(
        f'{BASE_URL}/agents/configuration',
        status_code=200,
        json=mock_set_agent_mode_http_reponse)

    mock_set_agent_mode_update_test = util_load_json('test_data/set_agent_mode_update_test.json')

    client = Client(
        base_url=f'{BASE_URL}',
        verify=False,
        headers={
            'Authentication': TOKEN
        },
        auth=(USERNAME, PASSWORD)
    )

    args = {
        'uuid': 'BFEBFBFF000806EAL1HF8C4003Z',
        'host_identifier': 'DESKTOP-ANTONY',
        'ip_address': '192.168.100.120',
        'mode': 'Free'
    }

    response = sepio_set_agent_mode_command(client, args)

    assert response == mock_set_agent_mode_update_test


def test_sepio_set_agent_peripherals_mode(requests_mock):
    """Tests sepio-set-peripherals-mode command function.

    Configures requests_mock instance to generate the appropriate
    API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    from SepioPrimeAPI import Client, sepio_set_agent_peripherals_mode_command

    #  mock api http response
    mock_signin_http_response = util_load_json('test_data/signin_http_response.json')
    requests_mock.post(
        f'{BASE_URL}/auth/signin',
        json=mock_signin_http_response)

    mock_set_peripherals_mode_http_reponse = util_load_json('test_data/set_peripherals_mode_http_reponse.json')
    requests_mock.post(
        f'{BASE_URL}/peripherals/command',
        status_code=200,
        json=mock_set_peripherals_mode_http_reponse)

    mock_set_peripherals_mode_update_test = util_load_json('test_data/set_peripherals_mode_update_test.json')

    client = Client(
        base_url=f'{BASE_URL}',
        verify=False,
        headers={
            'Authentication': TOKEN
        },
        auth=(USERNAME, PASSWORD)
    )

    args = {
        'uuid': 'BFEBFBFF000806EAL1HF8C4003Z',
        'ip_address': '192.168.100.120',
        'host_identifier': 'DESKTOP-ANTONY',
        'vid': '046D',
        'pid': 'C31C',
        'mode': 'Approve'
    }

    response = sepio_set_agent_peripherals_mode_command(client, args)

    assert response == mock_set_peripherals_mode_update_test


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from SepioPrimeAPI import Client, fetch_incidents

    #  mock api http response
    mock_signin_http_response = util_load_json('test_data/signin_http_response.json')
    requests_mock.post(
        f'{BASE_URL}/auth/signin',
        json=mock_signin_http_response)

    mock_fetch_incidents_http_response = util_load_json('test_data/fetch_incidents_http_response.json')
    requests_mock.get(
        f'{BASE_URL}/events/getevents?pageSize=20&'
        'pageNumber=1&sortBy=date_asc&minimumSeverity=Warning&'
        'fromDate=2020-06-22T12%3A00%3A00.000Z',
        json=mock_fetch_incidents_http_response)

    mock_fetch_incidents_query_test = util_load_json('test_data/fetch_incidents_query_test.json')

    client = Client(
        base_url=f'{BASE_URL}',
        verify=False,
        headers={
            'Authentication': TOKEN
        },
        auth=(USERNAME, PASSWORD)
    )

    last_run = {
        'last_fetch': '2020-06-22T12:00:00Z'
    }

    categories = [
        'USB',
        'Network'
    ]

    new_last_run, new_incidents = fetch_incidents(
        client=client,
        last_run=last_run,
        first_fetch_time='1 Day',
        min_serverity='Warning',
        categories=categories,
        max_results=20)

    mock_new_last_run = {
        'last_fetch': '2020-06-22T17:27:06Z',
        'last_fetch_eventid': 406}
    }

    assert new_last_run == mock_new_last_run
    assert new_incidents == mock_fetch_incidents_query_test
