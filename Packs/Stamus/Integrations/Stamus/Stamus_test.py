
import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


# TODO: ADD HERE unit tests for every command
def test_fetch_incidents(requests_mock):
    """
    Tests the fetch-incidents command function.

        Given:
            - requests_mock instance to generate the appropriate get_alert API response,
              loaded from a local JSON file.

        When:
            - Running the 'fetch_incidents' command.

        Then:
            - Checks the output of the command function with the expected output.
    """
    from Stamus import Client, fetch_incidents

    url = 'https://stamus-test.com/rest/appliances/threat_history_incident/?timestamp=1689340848&page_size=200'
    mock_response = util_load_json('test_data/fetch_incidents.json')
    requests_mock.get(url, json=mock_response)

    client = Client(
        base_url='https://stamus-test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    _, new_incidents = fetch_incidents(
        client=client,
        timestamp=1689340848
    )

    assert new_incidents == [{
        "name": "10.11.13.101_incident_0",
        "dbotMirrorId": "283115",
        "rawJSON": json.dumps(mock_response['results'][0]),
        "details": "description of my custom threat",
        "occurred": "2023-07-14T15:20:48.231617+02:00",
        "type": "ip"
    }]


def test_fetch_by_ioc(requests_mock):
    '''
        Given:
            - key/value to check.

        When:
            - Running the 'fetch_by_ioc'.

        Then:
            - Checks that results are the same than the ones built in tests.
    '''
    from Stamus import Client, fetch_by_ioc, CommandResults, tableToMarkdown, get_command_results

    filter = ('src_ip', '10.7.5.101')
    url = f'https://stamus-test.com/rest/rules/es/events_tail/?qfilter={filter[0]}%3A{filter[1]}'
    mock_response = util_load_json('test_data/fetch_by_ioc.json')
    requests_mock.get(url, json=mock_response)

    client = Client(
        base_url='https://stamus-test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    events = fetch_by_ioc(
        client,
        args={
            'indicator_key': filter[0],
            'indicator_value': filter[1]
        }
    )
    results = mock_response.get('results', [])
    table = tableToMarkdown('IOC Matches', results, headers=['timestamp', 'src_ip', 'dest_ip', 'event_type'])

    cmd_results = get_command_results(results, table, 'IOC')

    for key in cmd_results.__dict__:
        assert cmd_results.__dict__.get(key) == events.__dict__.get(key)
    assert events.raw_response == mock_response['results']
    assert isinstance(events, CommandResults)
    assert events.outputs_prefix == 'StamusIntegration.IOC'


def test_fetch_events(requests_mock):
    '''
        Given:
            - An id address to check.

        When:
            - Running the 'fetch_events'.

        Then:
            - Checks that results are the same than the ones built in tests.
    '''
    from Stamus import Client, fetch_events, CommandResults, tableToMarkdown, get_command_results

    id_to_check = 3
    url = f'https://stamus-test.com/rest/appliances/threat_history_incident/{id_to_check}/get_events'
    mock_response = util_load_json('test_data/fetch_events.json')
    requests_mock.get(url, json=mock_response)

    client = Client(
        base_url='https://stamus-test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    events = fetch_events(
        client,
        args={'id': id_to_check}
    )
    results = mock_response.get('results', [])
    for result in results:
        result['method'] = result.get('alert', {}).get('signature', 'algorithmic detection')
        result['info'] = ""
        if result.get("hostname_info"):
            result['info'] = 'Hostname: %s' % (result.get('hostname_info', {}).get('host', 'unknown'))
        result['asset'] = result.get('stamus', {}).get('asset', 'unknown')
        result['offender'] = result.get('stamus', {}).get('source', 'unknown')
        result['killchain'] = result.get('stamus', {}).get('kill_chain', 'unknown')
    headers = ['timestamp', 'asset', 'offender', 'killchain', 'method', 'info', 'src_ip', 'dest_ip', 'app_proto']
    table = tableToMarkdown('Individual Events List', results, headers=headers)

    cmd_results = get_command_results(results, table, 'RelatedEvents')

    for key in cmd_results.__dict__:
        assert cmd_results.__dict__.get(key) == events.__dict__.get(key)
    assert events.raw_response == mock_response['results']
    assert isinstance(events, CommandResults)
    assert events.outputs_prefix == 'StamusIntegration.RelatedEvents'


def test_fetch_host_id(requests_mock):
    '''
        Given:
            - An ip address to check.

        When:
            - Running the 'fetch_host_id'.

        Then:
            - Checks that results are the same than the ones built in tests.
    '''
    from Stamus import Client, fetch_host_id, CommandResults, tableToMarkdown, get_command_results, linearize_host_id

    ip = '217.116.0.227'
    url = f'https://stamus-test.com/rest/appliances/host_id/{ip}'
    mock_response = util_load_json('test_data/fetch_host_id.json')
    requests_mock.get(url, json=mock_response)

    client = Client(
        base_url='https://stamus-test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    events = fetch_host_id(
        client,
        args={'ip': ip}
    )
    results = mock_response
    headers = ['timestamp', 'ip', 'type', 'value']
    host_info = linearize_host_id(results)
    table = tableToMarkdown('Host Insight', host_info, headers=headers)

    cmd_results = get_command_results(results, table, 'HostInsights')

    for key in cmd_results.__dict__:
        assert cmd_results.__dict__.get(key) == events.__dict__.get(key)
    assert cmd_results.readable_output == table
    assert cmd_results.outputs == results
    assert events.raw_response == results
    assert isinstance(events, CommandResults)
    assert events.outputs_prefix == 'StamusIntegration.HostInsights'
