 

import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


 
def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, fetch_incidents

    mock_response = util_load_json('test_data/search_alerts.json')
    requests_mock.get(
        'https://test.com/api/v1/get_alerts?alert_status=ACTIVE'
        '&severity=Low%2CMedium%2CHigh%2CCritical&max_results=2'
        '&start_time=1581944401', json=mock_response['alerts'])

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    last_run = {
        'last_fetch': 1581944401  # Mon Feb 17 2020
    }

    _, new_incidents = fetch_incidents(
        client=client,
        max_results=2,
        last_run=last_run,
        alert_status='ACTIVE',
        min_severity='Low',
        alert_type=None,
        first_fetch_time='3 days',
    )

    assert new_incidents == [
        {
            'name': 'Hello World Alert 100',
            'occurred': '2020-02-17T23:34:23.000Z',
            'rawJSON': json.dumps(mock_response['alerts'][0]),
            'severity': 4,  # critical, this is XSOAR severity (already converted)
        },
        {
            'name': 'Hello World Alert 200',
            'occurred': '2020-02-17T23:34:23.000Z',
            'rawJSON': json.dumps(mock_response['alerts'][1]),
            'severity': 2,  # medium, this is XSOAR severity (already converted)
        }
    ]
