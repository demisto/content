# import demistomock as demisto
# from CommonServerPython import *
# from CommonServerUserPython import *
"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all function names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""
from CommonServerPython import *
from Armorblox import Client, get_incident_message_ids, get_remediation_action, get_incidents_list, \
    fetch_incidents_command
import io
import json

API_KEY = 'any-api-key'
TENANT_NAME = 'TestIntegration'
ARMORBLOX_INCIDENT_API_PATH = "api/v1beta1/organizations/{}/incidents"
url = "https://{}.armorblox.io/{}".format(TENANT_NAME, ARMORBLOX_INCIDENT_API_PATH.format(TENANT_NAME))


class MockResponse:
    def __init__(self, data, status_code):
        self.data = data
        self.text = str(data)
        self.status_code = status_code


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_response(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return MockResponse(f.read(), 200)


def mock_client(mocker, http_request_result=None, throw_error=False):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'current_refresh_token': 'refresh_token'})
    client = Client(api_key=API_KEY, instance_name=TENANT_NAME)
    if http_request_result:
        mocker.patch.object(client, '_http_request', return_value=http_request_result)

    if throw_error:
        err_msg = "Error in API call [400] - BAD REQUEST"
        mocker.patch.object(client, '_http_request', side_effect=DemistoException(err_msg, res={}))

    return client


def test_get_incident_message_ids(requests_mock):
    """Tests get_incident_message_ids function.
    Configures requests_mock instance to generate the appropriate start_scan
    API response when the correct start_scan API request is performed. Checks
    the output of the function with the expected output.
    """
    mock_response = util_load_json("test_data/test_get_incident_message_ids.json")
    requests_mock.get(url + '/3875', json=mock_response)
    client = Client(api_key=API_KEY, instance_name=TENANT_NAME)
    response = get_incident_message_ids(client, '3875')
    assert response == ["n9orMIXBQF6wKtRYpwb0Dg@geopod-ismtpd-4-0"]


def test_get_remediation_action(requests_mock):
    """Tests the armorblox-check-remediation-action command function.
    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    mock_response = util_load_json("test_data/test_get_remediation_action.json")
    requests_mock.get(url + '/3875', json=mock_response)
    client = Client(api_key=API_KEY, instance_name=TENANT_NAME)
    response = get_remediation_action(client, "3875")
    assert response.outputs['remediation_actions'] == 'ALERT'


def test_get_incidents_list(requests_mock):
    """Tests the get_incidents_list command function.
    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    mock_response = util_load_json("test_data/test_get_incidents_list.json")
    requests_mock.get(url + '?orderBy=ASC&pageToken=51&timeFilter=lastDay', json=mock_response)
    # response for the incident id, to populate message ids
    mock_response_for_incident_id = util_load_json("test_data/test_response_for_6484.json")
    requests_mock.get(url + '/6484', json=mock_response_for_incident_id)
    client = Client(api_key=API_KEY, instance_name=TENANT_NAME)
    response, pageToken = get_incidents_list(client, pageToken=51, first_fetch="lastDay")
    assert response == util_load_json("test_data/test_response_for_get_incidents_list.json")['incidents']


def test_fetch_incidents_command(requests_mock):
    """Tests the fetch_incidents_command command function.
    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    # get incidents function
    incidents_response = util_load_json("test_data/test_get_incidents_list.json")
    requests_mock.get(url + '?orderBy=ASC&pageSize=1', json=incidents_response)
    requests_mock.get(url + '?orderBy=ASC', json=incidents_response)
    # get message ids function
    mock_response_for_incident_id = util_load_json("test_data/test_response_for_6484.json")
    requests_mock.get(url + '/6484', json=mock_response_for_incident_id)
    client = Client(api_key=API_KEY, instance_name=TENANT_NAME)
    response = fetch_incidents_command(client)
    assert ('rawJSON' in response[0].keys()) is True
    assert ('details' in response[0].keys()) is True
