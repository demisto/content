import dateparser
import demistomock as demisto
from Claroty import Client, fetch_incidents

MOCK_AUTHENTICATION = {
    "first_name": "admin",
    "id": 1,
    "last_name": "admin",
    "mail": "admin",
    "password_expired": False,
    "token": "ok",
    "username": "admin"
}
RESOLVE_ALERT_RESPONSE = {
    "success": True
}
GET_ASSETS_RESPONSE = {
    "count_filtered": 1,
    "count_in_page": 1,
    "count_total": 1,
    "objects": [{
        "asset_type": 2,
        "asset_type__": "eEndpoint",
        "class_type": "IT",
        "criticality": 0,
        "criticality__": "eLow",
        "id": 15,
        "insight_names": ["Unsecured Protocols", "Windows CVEs"],
        "ipv4": ["1.1.1.1"],
        "last_seen": "2020-02-16T10:46:00+00:00",
        "mac": ["00:0B:AB:1A:DD:DD"],
        "name": "GTWB",
        "project_parsed": None,
        "resource_id": "15-1",
        "risk_level": 0,
        "site_id": 1,
        "site_name": "site-1",
        "vendor": "Advantech Technology",
        "virtual_zone_name": "Endpoint: Other"
    }]
}
GET_ALERTS_RESPONSE = {
    "count_filtered": 1,
    "count_in_page": 1,
    "count_total": 1,
    "objects": [{
        "actionable_assets": [{
            "actionable_id": 15,
            "asset": {
                "asset_type": 2,
                "asset_type__": "eEndpoint",
                "hostname": "GTWB",
                "id": 15,
                "ip": ["1.1.1.1"],
                "mac": ["00:0B:AB:1A:DD:DD"],
                "name": "GTWB",
                "network_id": 1,
                "os": "Windows XP",
                "resource_id": "15-1",
                "site_id": 1,
                "vendor": "Advantech Technology"
            },
            "id": 174,
            "resource_id": "174-1",
            "role": 5,
            "role__": "ePrimary",
            "site_id": 1
        }],
        "alert_indicators": [{
            "alert_id": 48,
            "id": 16,
            "indicator_id": 2,
            "indicator_info": {
                "description": "Event occurred out of working hours",
                "id": 2,
                "points": 10,
                "site_id": 1,
                "type": 1
            },
            "indicator_result": False,
            "parent_indicator_id": None,
            "site_id": 1
        }],
        "description": "A configuration has been downloaded to controller [[Chemical_plant]] by [[1.1.1.1]],"
                       " by user ENG_AB\\Administrator",
        "network_id": 1,
        "resolved": False,
        "resource_id": "48-1",
        "severity": 3,
        "severity__": "eCritical",
        "type": 1001,
        "type__": "eConfigurationDownload",
        "timestamp": "2020-02-16T10:46:00+00:00"
    }]
}


def _create_client(mocker, requests_mock, request_url, response_json, request_type, **extra_params):
    mocker.patch.object(demisto, 'params', return_value={
        "credentials": {
            'identifier': 'user',
            'password': 'omgSecretsWow',
        },
        'url': 'https://website.com',
        'fetch_time': '7 days'
    })

    requests_mock.post('https://website.com:5000/auth/authenticate', json=MOCK_AUTHENTICATION)
    if request_type == "POST" and request_url != 'https://website.com:5000/auth/authenticate':
        requests_mock.post(request_url, json=response_json)
    elif request_type == "GET":
        requests_mock.get(request_url, json=response_json)

    mocker.patch.object(demisto, 'args', return_value={})
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    base_url = demisto.params()['url'].rstrip('/') + ':5000'
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        credentials=(username, password),
        proxy=proxy,
    )

    return client


def test_claroty_authentication(mocker, requests_mock):
    client = _create_client(mocker, requests_mock, 'https://website.com:5000/auth/authenticate',
                            MOCK_AUTHENTICATION, "POST")

    token = client._generate_token()["jwt_token"]
    assert token == 'ok'


def test_claroty_fetch_incidents(mocker, requests_mock):
    client = _create_client(mocker, requests_mock, "https://website.com:5000/ranger/alerts", GET_ALERTS_RESPONSE, "GET")
    first_fetch_time = demisto.params().get('fetch_time', '7 days').strip()
    mocker.patch.object(demisto, 'incidents')
    nextcheck, incidents = fetch_incidents(client, {'lastRun': dateparser.parse("2018-10-24T14:13:20+00:00")}, first_fetch_time)

    assert nextcheck['last_fetch']
    assert isinstance(incidents, list)
    assert incidents[0]['severity'] == 4  # Demisto severity is higher by one (doesn't start at 0)
    assert isinstance(incidents[0]['name'], str)


def test_claroty_query_alerts(mocker, requests_mock):
    client = _create_client(mocker, requests_mock, "https://website.com:5000/ranger/alerts", GET_ALERTS_RESPONSE, "GET")

    response = client.get_alerts([], {}, [])
    assert response["objects"][0]["resource_id"] == "48-1"
    assert response["objects"][0]["severity"] == 3
    assert response["objects"][0]["alert_indicators"]


def test_claroty_get_assets(mocker, requests_mock):
    client = _create_client(mocker, requests_mock, "https://website.com:5000/ranger/assets", GET_ASSETS_RESPONSE, "GET")

    response = client.get_assets([], {}, [])
    assert response["objects"][0]["resource_id"] == "15-1"
    assert response["objects"][0]["name"] == "GTWB"
    assert response["objects"][0]["criticality"] == 0


def test_claroty_resolve_alerts(mocker, requests_mock):
    client = _create_client(mocker, requests_mock, 'https://website.com:5000/ranger/ranger_api/resolve_alerts',
                            RESOLVE_ALERT_RESPONSE, "POST")

    response = client.resolve_alert(['1-1'], {}, 1, "Test is good")
    assert response["success"]
