import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_incidents(requests_mock):

    from QSS import Client, fetch_incidents

    mock_response = util_load_json('test_data/soc_monitoring_cases.json')
    requests_mock.get(
        'https://test.com/api/v1/get_alerts?apikey=5Xcaadf7b17e4c5e679d2a851a91a2&duration=48', json=mock_response['alerts'])

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={}
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
            'name': 'SOC Case CAS-4-20210125-1',
            'occurred': '2021-01-27T11:16:11Z',
            'rawJSON': json.dumps(mock_response['alerts'][0]),
            'severity': 2,  # medium, this is XSOAR severity (already converted)
        },
        {
            'name': 'SOC Case CAS-4-20210125-2',
            'occurred': '2021-01-27T11:16:11Z',
            'rawJSON': json.dumps(mock_response['alerts'][1]),
            'severity': 3,  # high, this is XSOAR severity (already converted)
        }
    ]
