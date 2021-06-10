import json
import io
import dateparser
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


"""*****COMMAND FUNCTIONS****"""


def test_fetch_incidents(requests_mock):

    from Linkshadow import Client, fetch_incidents

    test_api_response = util_load_json('test_data/fetch_incident.json')
    requests_mock.post('https://LS_test_fetch_incidents.com/api/plugin/', json=test_api_response)
    client = Client(
        base_url='https://LS_test_fetch_incidents.com/',
        verify=False,
        proxy=False)
    last_run = {
        'last_fetch': dateparser.parse(str(1621860339000), settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)
    }
    integration_response = fetch_incidents(
        client=client,
        max_alerts=20,
        last_run=last_run,
        first_fetch_time='1 day ago',
        apiKey="",
        api_username="lsadmin",
        plugin_id="xsoar_integration_1604211382",
        action="fetch_entity_anomalies"
    )
    expected_response = util_load_json('test_data/formatted_fetch_incident.json')
    responsejson = integration_response[1][0]
    responsejson['rawJSON'] = json.loads(responsejson['rawJSON'])

    assert responsejson == expected_response[0]


def test_fetch_entity_anomalies(requests_mock):

    from Linkshadow import Client, fetch_entity_anomalies

    test_api_response = util_load_json('test_data/fetch_anomaly.json')
    requests_mock.post('https://LS_test_fetch_anomaly.com/api/plugin/', json=test_api_response)
    client = Client(
        base_url='https://LS_test_fetch_anomaly.com/',
        verify=False,
        proxy=False)
    params = {
        'apiKey': '',
        'username': 'lsadmin',
        'plugin_id': 'xsoar_integration_1604211382',
        'action': 'fetch_entity_anomalies',
    }
    args = {
        'time_frame': '01'
    }
    integration_response = fetch_entity_anomalies(client, params, args)
    expected_response = util_load_json('test_data/formatted_fetch_anomaly.json')
    # raise ValueError(integration_response.outputs, expected_response)
    assert integration_response.outputs == expected_response
    assert integration_response.outputs_key_field == 'GlobalID'
    assert integration_response.outputs_prefix == 'Linkshadow.data'
