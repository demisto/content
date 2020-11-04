"""
Test Execution
--------------

Unit tests can be checked in 3 ways:
- Using the command `lint` of demisto-sdk. The command will build a dedicated
  docker instance for your integration locally and use the docker instance to
  execute your tests in a dedicated docker instance.
- From the command line using `pytest -v` or `pytest -vv`
- From PyCharm

Example with demisto-sdk (from the content root directory):
demisto-sdk lint -i Packs/HelloWorld/Integrations/HelloWorld

"""
import pytest


def test_handle_sysparms():
    """
    Tests snow-cdmb-handle-sysparms function.
    Given:
        - A list of sysparms and a dictionary representing the desired value of each sysparm.
    When:
        - Running the handle_sysparm function.
    Then:
        - Validate that the params dictionary created by the function matches the desired output.
    """
    from ServiceNow_CMDB import handle_sysparms
    from test_data.result_constants import EXPECTED_PARAMS_DICT
    from test_data.response_constants import HANDLE_SYSPARMS_ARGS, HANDLE_SYSPARMS_PARAMS

    num_tests = len(EXPECTED_PARAMS_DICT)
    for i in range(num_tests):
        params = handle_sysparms(HANDLE_SYSPARMS_PARAMS[i], HANDLE_SYSPARMS_ARGS)
        assert params == EXPECTED_PARAMS_DICT[i]


def test_say_hello():
    """Tests helloworld-say-hello command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the say_hello_command does not call
    any external API.
    """
    from HelloWorld import Client, say_hello_command

    client = Client(base_url='https://test.com/api/v1', verify=False, auth=('test', 'test'))
    args = {
        'name': 'Dbot'
    }
    response = say_hello_command(client, args)

    assert response.outputs == 'Hello Dbot'


def test_start_scan(requests_mock):
    """Tests helloworld-scan-start command function.

    Configures requests_mock instance to generate the appropriate start_scan
    API response when the correct start_scan API request is performed. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, scan_start_command

    mock_response = {
        'scan_id': '7a161a3f-8d53-42de-80cd-92fb017c5a12',
        'status': 'RUNNING'
    }
    requests_mock.get('https://test.com/api/v1/start_scan?hostname=example.com', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'hostname': 'example.com'
    }

    response = scan_start_command(client, args)

    assert response.outputs_prefix == 'HelloWorld.Scan'
    assert response.outputs_key_field == 'scan_id'
    assert response.outputs == {
        'scan_id': '7a161a3f-8d53-42de-80cd-92fb017c5a12',
        'status': 'RUNNING',
        'hostname': 'example.com'
    }


def test_status_scan(requests_mock):
    """Tests helloworld-scan-status command function.

    Configures requests_mock instance to generate the appropriate check_scan
    API responses based on the scan ID provided. For scan_id 100, 300 status
    should be COMPLETE while for scan ID 200 is RUNNING. Checks the output of
    the command function with the expected output.
    """
    from HelloWorld import Client, scan_status_command

    mock_response = {
        'scan_id': '100',
        'status': 'COMPLETE'
    }
    requests_mock.get('https://test.com/api/v1/check_scan?scan_id=100', json=mock_response)

    mock_response = {
        'scan_id': '200',
        'status': 'RUNNING'
    }
    requests_mock.get('https://test.com/api/v1/check_scan?scan_id=200', json=mock_response)

    mock_response = {
        'scan_id': '300',
        'status': 'COMPLETE'
    }
    requests_mock.get('https://test.com/api/v1/check_scan?scan_id=300', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'scan_id': ['100', '200', '300']
    }

    response = scan_status_command(client, args)

    assert response.outputs_prefix == 'HelloWorld.Scan'
    assert response.outputs_key_field == 'scan_id'
    assert response.outputs == [
        {
            'scan_id': '100',
            'status': 'COMPLETE'
        },
        {
            'scan_id': '200',
            'status': 'RUNNING'
        },
        {
            'scan_id': '300',
            'status': 'COMPLETE'
        }
    ]


def test_scan_results(mocker, requests_mock):
    """Tests helloworld-scan-results command function.

    Configures requests_mock instance to generate the appropriate
    get_scan_results API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, scan_results_command
    from CommonServerPython import Common

    mock_response = util_load_json('test_data/scan_results.json')
    requests_mock.get('https://test.com/api/v1/get_scan_results?scan_id=100', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'scan_id': '100',
        'format': 'json'
    }

    response = scan_results_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'HelloWorld.Scan'
    assert response.outputs_key_field == 'scan_id'

    # This command also returns Common.CVE data
    assert isinstance(response.indicators, list)
    assert len(response.indicators) > 0
    assert isinstance(response.indicators[0], Common.CVE)


def test_search_alerts(requests_mock):
    """Tests helloworld-search-alerts command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, search_alerts_command

    mock_response = util_load_json('test_data/search_alerts.json')
    requests_mock.get(
        'https://test.com/api/v1/get_alerts?alert_status=ACTIVE&severity=Critical&max_results=2&start_time=1581982463',
        json=mock_response['alerts'])

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'severity': 'Critical',
        'start_time': 1581982463,
        'max_results': 2,
        'status': 'ACTIVE'
    }

    response = search_alerts_command(client, args)

    # We modify the timestamp from the raw mock_response of the API, because the
    # integration changes the format from timestamp to ISO8601.
    mock_response['alerts'][0]['created'] = '2020-02-17T23:34:23.000Z'
    mock_response['alerts'][1]['created'] = '2020-02-17T23:34:23.000Z'

    assert response.outputs_prefix == 'HelloWorld.Alert'
    assert response.outputs_key_field == 'alert_id'
    assert response.outputs == mock_response['alerts']


def test_get_alert(requests_mock):
    """Tests helloworld-get-alert command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, get_alert_command

    mock_response = util_load_json('test_data/get_alert.json')
    requests_mock.get('https://test.com/api/v1/get_alert_details?alert_id=695b3238-05d6-4934-86f5-9fff3201aeb0',
                      json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'alert_id': '695b3238-05d6-4934-86f5-9fff3201aeb0',
    }

    response = get_alert_command(client, args)

    # We modify the timestamp from the raw mock_response of the API, because the
    # integration changes the format from timestamp to ISO8601.
    mock_response['created'] = '2020-04-17T14:43:59.000Z'

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'HelloWorld.Alert'
    assert response.outputs_key_field == 'alert_id'


def test_update_alert_status(requests_mock):
    """Tests helloworld-update-alert-status command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, update_alert_status_command

    mock_response = util_load_json('test_data/update_alert_status.json')
    requests_mock.get(
        'https://test.com/api/v1/change_alert_status?alert_id=695b3238-05d6-4934-86f5-9fff3201aeb0&alert_status=CLOSED',
        json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'alert_id': '695b3238-05d6-4934-86f5-9fff3201aeb0',
        'status': 'CLOSED'
    }

    response = update_alert_status_command(client, args)

    # We modify the timestamp from the raw mock_response of the API, because the
    # integration changes the format from timestamp to ISO8601.
    mock_response['updated'] = '2020-04-17T14:45:12.000Z'

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'HelloWorld.Alert'
    assert response.outputs_key_field == 'alert_id'




