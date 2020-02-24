from HelloWorld import Client, say_hello_command, scan_start_command, scan_results_command, scan_status_command, \
search_alerts_command, ip_reputation_command, fetch_incidents
import json
import io


def testutil_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_say_hello():
    client = Client(base_url='https://test.com', verify=False, auth=('test', 'test'))
    args = {
        'name': 'Dbot'
    }
    _, outputs, _ = say_hello_command(client, args)

    assert outputs['hello'] == 'Hello Dbot'


def test_start_scan(requests_mock):
    mock_response = {
        "scan_id": "7a161a3f-8d53-42de-80cd-92fb017c5a12",
        "status": "RUNNING"
    }
    requests_mock.get('http://test.com/start_scan?hostname=example.com', json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'some_api_key'
        }
    )

    args = {
        'hostname': 'example.com'
    }

    _, outputs, _ = scan_start_command(client, args)

    assert outputs == {
        'HelloWorld.Scan(val.scan_id == obj.scan_id)': {
            "scan_id": "7a161a3f-8d53-42de-80cd-92fb017c5a12",
            "status": "RUNNING"
        }
    }


def test_status_scan(requests_mock):
    mock_response = {
        "scan_id": "100",
        "status": "COMPLETE"
    }
    requests_mock.get('http://test.com/check_scan?scan_id=100', json=mock_response)

    mock_response = {
        "scan_id": "200",
        "status": "RUNNING"
    }
    requests_mock.get('http://test.com/check_scan?scan_id=200', json=mock_response)

    mock_response = {
        "scan_id": "300",
        "status": "COMPLETE"
    }
    requests_mock.get('http://test.com/check_scan?scan_id=300', json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'some_api_key'
        }
    )

    args = {
        'scan_id': ['100', '200', '300']
    }

    _, outputs, _ = scan_status_command(client, args)

    assert outputs == {
        'HelloWorld.Scan(val.scan_id == obj.scan_id)': [
            {
                "scan_id": "100",
                "status": "COMPLETE"
            },
            {
                "scan_id": "200",
                "status": "RUNNING"
            },
            {
                "scan_id": "300",
                "status": "COMPLETE"
            }
        ]
    }


def test_scan_results(mocker, requests_mock):
    import demistomock as demisto
    mock_response = testutil_load_json('test_data/scan_results.json')
    requests_mock.get('http://test.com/get_scan_results?scan_id=100', json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'some_api_key'
        }
    )

    args = {
        'scan_id': '100',
        'format': 'json'
    }

    # return_outputs calls demisto.results,
    # that is the reason we patch demisto.results
    mocker.patch.object(demisto, 'results')

    scan_results_command(client, args)

    assert demisto.results.call_count == 1

    outputs = demisto.results.call_args[0][0]['EntryContext']
    assert outputs == {
        'HelloWorld.Scan(val.scan_id == obj.scan_id)': mock_response
    }


def test_search_alerts(requests_mock):
    mock_response = testutil_load_json('test_data/search_alerts.json')
    requests_mock.get('http://test.com/get_alerts?alert_status=ACTIVE&severity=4&max_results=2&start_time=1581982463',
                      json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'some_api_key'
        }
    )

    args = {
        'severity': 4,
        'start_time': 1581982463,
        'max_results': 2,
        'status': 'ACTIVE'
    }

    _, outputs, _ = search_alerts_command(client, args)

    assert outputs == {
        'HelloWorld.Alert(val.alert_id == obj.alert_id)': mock_response
    }


def test_fetch_incidents(requests_mock):
    mock_response = testutil_load_json('test_data/search_alerts.json')
    requests_mock.get('http://test.com/get_alerts?alert_status=ACTTIVE&max_results=50&start_time=1582584487883',
                      json=mock_response)

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'some_api_key'
        }
    )

    last_run = {
        'last_fetch': 1582584487883  # Mon Feb 24 2020 22:48:07
    }

    next_run, new_incidents = fetch_incidents(
        client=client,
        last_run=last_run,
        alert_status='ACTTIVE',
        alert_type=None,
        first_fetch_time='3 days'
    )

    assert new_incidents == [
        {
            'name': '#100 - Hello World Alert 100',
            'details': 'Hello World Alert 100',
            'occurred': '2020-02-18T01:34:23.000Z',
            'rawJSON': json.dumps(mock_response[0])
        },
        {
            'name': '#200 - Hello World Alert 200',
            'details': 'Hello World Alert 200',
            'occurred': '2020-02-18T01:34:23.000Z',
            'rawJSON': json.dumps(mock_response[1])
        }
    ]
