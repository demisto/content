import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


"""*****COMMAND FUNCTIONS****"""


def test_fetch_incidents(requests_mock):

    from Linkshadow import Client, fetch_incidents

    test_api_response = util_load_json('test_data/fetch_incident.json')
    requests_mock.post('https://LS_test_fetch_incidents.com/api/plugin/',
                      json=test_api_response)
    
    client = Client(
            base_url='https://LS_test_fetch_incidents.com/',
            verify=False,
            proxy=False)
    
    last_run = {
        'last_fetch': 1621933263000  # Mon, Aug 31, 2020 9 PM Pacific
    }
    # WHEN the desired anomaly has 
    integration_response = fetch_incidents(
        client = client,
        max_alerts=20,
        last_run=last_run,
        first_fetch_time='1 day ago',
        apiKey = "",
        api_username = "lsadmin"    ,
        plugin_id = "xsoar_integration_1604211382",
        action = "fetch_entity_anomalies",
        time_frame = "10",
    )
    
    expected_response = util_load_json('test_data/formatted_fetch_incident.json')
    raise ValueError(integration_response,":::::",expected_response)
    # THEN the response should be returned and formatted
    assert integration_response == expected_response
 