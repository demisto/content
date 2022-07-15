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
from Armorblox import Client, get_incident_message_ids, get_remediation_action, get_incidents_list, get_page_token, \
    fetch_incidents_command
import io
import json
BASE_URL = "https://test.com"
API_KEY = "<some api key>"
payload: Dict = {}
headers = {'Authorization': f"Bearer {API_KEY}"}


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
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        auth=None,
        headers=headers
    )
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
    requests_mock.get('https://test.com/api/v1/incidents/3875', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = get_incident_message_ids(client, '3875')
    assert response == ["n9orMIXBQF6wKtRYpwb0Dg@geopod-ismtpd-4-0"]


def test_get_remediation_action(requests_mock):
    """Tests the armorblox-check-remediation-action command function.
    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    mock_response = util_load_json("test_data/test_get_remediation_action.json")
    requests_mock.get('https://test.com/api/v1/incidents/3875', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = get_remediation_action(client, "3875")
    assert response.outputs['remediation_actions'] == 'ALERT'


def test_get_incidents_list(requests_mock):
    """Tests the fetch_incidents_command command function.
    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    mock_response = util_load_json("test_data/test_get_incidents_list.json")
    requests_mock.get('https://test.com/api/v1/incidents?orderBy=ASC&pageToken=51&timeFilter=lastDay', json=mock_response)
    # response for the incident id, to populate message ids
    mock_response_for_incident_id = util_load_json("test_data/test_response_for_6484.json")
    requests_mock.get('https://test.com/api/v1/incidents/6484', json=mock_response_for_incident_id)
    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = get_incidents_list(client, pageToken=51, first_fetch="lastDay")
    assert response == util_load_json("test_data/test_response_for_get_incidents_list.json")['incidents']


def test_get_page_token(requests_mock):
    """Tests the get_page_token command function.
    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    mock_response = util_load_json("test_data/test_get_incidents_list.json")
    requests_mock.get('https://test.com/api/v1/incidents?orderBy=ASC', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = get_page_token(client)
    assert response == "1"


def test_fetch_incidents_command(requests_mock):
    """Tests the fetch_incidents_command command function.
    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    # get incidents function
    incidents_response = util_load_json("test_data/test_get_incidents_list.json")
    requests_mock.get('https://test.com/api/v1/incidents?orderBy=ASC&pageSize=1', json=incidents_response)
    requests_mock.get('https://test.com/api/v1/incidents?orderBy=ASC', json=incidents_response)
    # get message ids function
    mock_response_for_incident_id = util_load_json("test_data/test_response_for_6484.json")
    requests_mock.get('https://test.com/api/v1/incidents/6484', json=mock_response_for_incident_id)
    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_incidents_command(client)
    assert ('rawJSON' in response[0].keys()) is True
    assert ('details' in response[0].keys()) is True
