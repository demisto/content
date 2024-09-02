import json
import pytest

from CognyteLuminar import Client, cognyte_luminar_get_indicators, \
    cognyte_luminar_get_leaked_records, module_test, reset_last_run, \
    fetch_indicators_command, generic_item_finder, enrich_malware_items, \
    enrich_incident_items

client = Client(
    base_url="http://test.com",
    account_id="abcd1234",
    client_id="cognyte",
    client_secret="test",
    verify=False,
    proxy=False,
    tags=["TT1", "TT2"],
    tlp_color="RED"
)
generic_expected_output = {
    'created': '2016-02-01T00:00:00.000Z',
    'created_by_ref': 'identity--262928b4-f329-4436-9e81-6f35f69d8a85',
    'id': 'indicator--f0680d81-7ce7-4a04-8315-0d38f792b908',
    'indicator_types': ['malicious-activity'],
    'modified': '2016-02-01T00:00:00.000Z',
    'name': 'Imminent Monitor 4.1',
    'pattern': "[file:hashes.MD5 = '9dd8c0ff4fc84287e5b766563240f983']",
    'pattern_type': 'stix',
    'spec_version': '2.1',
    'type': 'indicator',
    'valid_from': '2016-02-01T00:00:00.000Z'
}
enrich_malware_output = {
    "value": "Ukraine Power Grid",
    "occurred": "01/04/2016, " + "00:00:00",
    "type": "Malware",
    "rawJSON": {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--0913cc2e-56a1-4c00-aafb-e3ce7a8d8940",
        "created": "2016-01-04T00:00:00.000Z",
        "modified": "2016-01-04T00:00:00.000Z",
        "malwareTypes": [
            "trojan"
        ],
        "is_family": False,
        "name": "Ukraine " + "Power " + "Grid"
    },
    "fields": {
        "STIX Is Malware Family": False,
        "tags": [
            "malicious-activity"
        ],
        "stixid": "malware--0913cc2e-56a1-4c00-aafb-e3ce7a8d8940",
        "STIX Malware Types": [
            "trojan"
        ],
        "malware_types": [
            "trojan"
        ]
    }
}

enrich_incident_output = {
    "type": "incident",
    "spec_version": "2.1",
    "id": "incident--9907916e-f213-4c08-bd91-6c2bf109e509",
    "created": "2021-02-02T00:00:00.000Z",
    "modified": "2021-02-02T00:00:00.000Z",
    "name": "Master Breach Comp",
    "created_by_ref": "identity--b276f696-62b2-4b5b-b8df-cda64e955399"
}


def load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


INDICATOR_LIST = load_json("test_data/indicator_list.json")
child_record = load_json("test_data/child.json")
lumanar_data = load_json("test_data/luminar_api_result.json")
indicator_list_output = load_json("test_data/indicator_list_record.json")
leaked_record_output = load_json("test_data/leaked_record_list.json")
user_account_record = load_json("test_data/luminar_user_account.json")


def test_test_module(mocker):
    mocker.patch.object(client, 'fetch_access_token', autospec=True)
    response = module_test(client)
    assert response == "ok"


def test_cognyte_luminar_get_indicators(mocker):
    mocker.patch.object(client, 'get_luminar_indicators_list',
                        side_effect=[INDICATOR_LIST])
    args = {"limit": 3}
    response = cognyte_luminar_get_indicators(client, args)
    assert len(response.outputs) == 3
    assert len(response.raw_response) == 3
    assert response.outputs_prefix == "Luminar.Indicators"


def test_cognyte_luminar_get_indicators_zero_limit(mocker):
    mocker.patch.object(client, 'get_luminar_indicators_list',
                        side_effect=[INDICATOR_LIST])
    args = {"limit": 0}
    response = cognyte_luminar_get_indicators(client, args)
    assert response.readable_output == "No Indicators Found."


def test_cognyte_luminar_get_indicators_without_limit(mocker):
    mocker.patch.object(client, 'get_luminar_indicators_list',
                        side_effect=[INDICATOR_LIST])
    args = {}
    response = cognyte_luminar_get_indicators(client, args)
    assert len(response.outputs) == 50
    assert len(response.raw_response) == 50
    assert response.outputs_prefix == "Luminar.Indicators"


def test_cognyte_luminar_get_leaked_records(mocker):
    mocker.patch.object(client, 'get_luminar_leaked_credentials_list',
                        side_effect=[INDICATOR_LIST])
    args = {
        "limit": 3
    }
    response = cognyte_luminar_get_leaked_records(client, args)

    assert len(response.outputs) == 3
    assert len(response.raw_response) == 3
    assert response.outputs_prefix == "Luminar.Leaked_Credentials"


def test_cognyte_luminar_get_leaked_records_without_limit(mocker):
    mocker.patch.object(client, 'get_luminar_leaked_credentials_list',
                        side_effect=[INDICATOR_LIST])
    args = {}
    response = cognyte_luminar_get_leaked_records(client, args)

    assert len(response.outputs) == 50
    assert len(response.raw_response) == 50
    assert response.outputs_prefix == "Luminar.Leaked_Credentials"


def test_cognyte_luminar_get_leaked_records_zero_limit(mocker):
    mocker.patch.object(client, 'get_luminar_leaked_credentials_list',
                        side_effect=[INDICATOR_LIST])
    args = {"limit": 0}
    response = cognyte_luminar_get_leaked_records(client, args)
    assert response.readable_output == "No Leaked Records Found."


def test_reset_last_run():
    response = reset_last_run()
    assert response.readable_output == "Fetch history deleted successfully"


def test_fetch_indicators_command(mocker):
    mocker.patch.object(client, 'fetch_luminar_indicators',
                        side_effect=[INDICATOR_LIST])
    response = fetch_indicators_command(client)
    assert str(response) == str(True)


@pytest.mark.parametrize('expected_optput', [(generic_expected_output)])
def test_generic_item_finder(expected_optput):
    response = generic_item_finder(INDICATOR_LIST,
                                   "indicator--f0680d81-7ce7-4a04-8315-0d38f792b908")
    result = {}
    for i in response:
        result.update(i)
    assert result == expected_optput


@pytest.mark.parametrize('expected_optput', [(enrich_malware_output)])
def test_enrich_malware_items(expected_optput):
    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--0913cc2e-56a1-4c00-aafb-e3ce7a8d8940",
        "created": "2016-01-04T00:00:00.000Z",
        "modified": "2016-01-04T00:00:00.000Z",
        "malwareTypes": [
            "trojan"
        ],
        "is_family": False
    },
    indicator = [ele for ele in INDICATOR_LIST if ele["type"] == "indicator"]
    parent, child = enrich_malware_items(malware[0], indicator, ["TT1",
                                                                 "TT2"], "RED")
    assert parent == expected_optput


@pytest.mark.parametrize('expected_optput', [(enrich_incident_output)])
def test_enrich_incident_items(expected_optput):
    user_account_list = [ele for ele in INDICATOR_LIST if
                         ele["type"] == "user-account"]
    incident = {
        "type": "incident",
        "spec_version": "2.1",
        "id": "incident--9907916e-f213-4c08-bd91-6c2bf109e509",
        "created": "2021-02-02T00:00:00.000Z",
        "modified": "2021-02-02T00:00:00.000Z",
        "name": "Master Breach Comp",
        "created_by_ref": "identity--b276f696-62b2-4b5b-b8df-cda64e955399"
    }
    parent, child = enrich_incident_items(incident, user_account_list, ["TT1", "TT2"], "RED")
    assert parent == expected_optput


def test_fetch_access_token(requests_mock):
    req_url = f"{client._base_url}/realm/{client.luminar_account_id}/token"
    req_headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8"
    }
    requests_mock.post(req_url, headers=req_headers, json={'access_token': '12345'})

    response = client.fetch_access_token()
    assert response == "12345"


def test_get_last_run(mocker):
    mocker.patch.object(client, "get_last_run", side_effect=[""])
    response = client.get_last_run()
    assert response == ""


def test_fetch_luminar_api_feeds(requests_mock):
    post_req_url = f"{client._base_url}/realm/{client.luminar_account_id}/token"
    get_req_url = f"{client._base_url}/stix"
    post_req_headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8"
    }
    requests_mock.post(post_req_url, headers=post_req_headers,
                       json={'access_token': '12345'})
    access_token = client.fetch_access_token()
    get_req_headers = {"Authorization": "Bearer %s" % access_token}
    requests_mock.get(get_req_url, headers=get_req_headers, json=lumanar_data)
    response = client.fetch_luminar_api_feeds()
    response_list = []
    for i in response:
        response_list = i
        break
    assert response_list == lumanar_data['objects']


def gen_indicator_list(Indicator):
    yield Indicator


def test_get_luminar_indicators_list(mocker, requests_mock):
    post_req_url = f"{client._base_url}/realm/{client.luminar_account_id}/token"
    get_req_url = f"{client._base_url}/stix"
    post_req_headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8"
    }
    requests_mock.post(post_req_url, headers=post_req_headers,
                       json={'access_token': '12345'})
    access_token = client.fetch_access_token()
    get_req_headers = {"Authorization": "Bearer %s" % access_token}
    requests_mock.get(get_req_url, headers=get_req_headers, json=lumanar_data)
    response = client.fetch_luminar_api_feeds()
    response_list = []
    for i in response:
        response_list.append(i)
        break
    gen_response = gen_indicator_list(response_list)
    mocker.patch.object(client, 'fetch_luminar_api_feeds',
                        side_effect=gen_response)
    response = client.get_luminar_indicators_list()
    assert response == indicator_list_output


def test_luminar_leaked_credentials_list(mocker, requests_mock):
    post_req_url = f"{client._base_url}/realm/{client.luminar_account_id}/token"
    get_req_url = f"{client._base_url}/stix"
    post_req_headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8"
    }
    requests_mock.post(post_req_url, headers=post_req_headers,
                       json={'access_token': '12345'})
    access_token = client.fetch_access_token()
    get_req_headers = {"Authorization": "Bearer %s" % access_token}
    requests_mock.get(get_req_url, headers=get_req_headers,
                      json=user_account_record)
    response = client.fetch_luminar_api_feeds()
    response_list = []
    for i in response:
        response_list.append(i)
        break
    gen_response = gen_indicator_list(response_list)
    mocker.patch.object(client, 'fetch_luminar_api_feeds',
                        side_effect=gen_response)
    response = client.get_luminar_leaked_credentials_list()
    assert response == leaked_record_output
