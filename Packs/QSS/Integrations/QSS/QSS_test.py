import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_incidents(requests_mock):

    from QSS import Client, fetch_incidents

    mock_response = util_load_json('test_data/soc_monitoring_cases.json')
    requests_mock.get('https://test.com/api/v1/rest/noauth/third_party/read_object/xsoar/v1', json=mock_response['alerts'])
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
        first_fetch_time='3 days',
        false_positive='No',
        api_key='aS5Xcaf7b17e4c5e679d2a851a91a2'
    )

    assert new_incidents == [
        {
            'name': 'SOC Case CAS-4-20210328-1',
            'occurred': '2021-03-28T13:42:39Z',
            'event_id': '2160',
            'rawJSON': json.dumps(mock_response['alerts'][0]),
            'severity': 1,  # medium, this is XSOAR severity (already converted)
        }
    ]
