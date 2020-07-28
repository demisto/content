import json
import os
import demistomock as demisto
from TrendMicroApex import list_logs_command, Client

MOCK_URL = "https://TrendMicro-fake-api.com"
MOCK_API_KEY = "a1b2c3d4e5"
MOCK_APP_ID = "a1b2c3d4e5"

client = Client(
    base_url=MOCK_URL,
    api_key=MOCK_API_KEY,
    app_id=MOCK_APP_ID,
    proxy=False,
    verify=False,
)


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


MOCK_LOGS_LIST = load_test_data('./test_data/logs_list_command_mock.json')
MOCK_ADD_FILE = load_test_data('./test_data/add_file_command_mock.json')
MOCK_SERVERS_LIST = load_test_data('./test_data/servers_list_command_mock.json')
MOCK_AGENTS_LIST = load_test_data('./test_data/agent_list_command_mock.json')
MOCK_SENSORS_LIST = load_test_data('./test_data/sensors_list_command_mock.json')
MOCK_HISTORICAL_INVESTIGATION = load_test_data('./test_data/historical_investigation_command_mock.json')
MOCK_RESULT_LIST = load_test_data('./test_data/result_list_command_mock.json')


def test_list_logs_command(requests_mock, mocker):
    """ Unit test
    Given
        - logs_list command
        - command args - log_type
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.
    Then
        Validate the content of the CommandResult
    """
    requests_mock.get(f'{MOCK_URL}/WebApp/api/v1/logs/web_security?output_format=1&page_token=0&since_time=0',
                      json=MOCK_LOGS_LIST)
    args = {
        'log_type': 'Web Violation'
    }
    mocker.patch.object(Client, 'create_jwt_token', return_value="fake_token")

    response = list_logs_command(client, args)
    outputs = response.outputs
    logs = outputs.get('Logs')
    assert logs
    assert len(logs) == 5
    assert logs[0].get('DeviceVendor')  # check that the cef parse was successful
    assert 'Logs List' in response.readable_output
    assert response.outputs_prefix == 'TrendMicroApex.Log'


def test_udso_file_add_command(requests_mock, mocker):
    """ Unit test
    Given
        - udso_file_add command
        - command args - file_scan_action, note, entry_id
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.
        - mock the response to the getFilePath method.

    Then
        Validate the content of the CommandResult
    """
    from TrendMicroApex import udso_file_add_command
    requests_mock.put(f'{MOCK_URL}/WebApp/api/SuspiciousObjectResource/FileUDSO', json=MOCK_ADD_FILE)
    mocker.patch.object(client, 'create_jwt_token', return_value="fake_token")

    file_path = os.path.join('test_data', 'file_example.txt')
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': file_path, 'name': 'file_example'})

    args = {
        'file_scan_action': 'Log',
        'note': 'example_note',
        'entry_id': 'fake_entry_id'
    }

    response = udso_file_add_command(client, args)
    assert '### The file "file_example" was added to the UDSO list successfully' in response.readable_output


def test_servers_list_command(requests_mock, mocker):
    """ Unit test
    Given
        - managed_servers_list command
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.

    Then
        Validate the content of the CommandResult
    """
    from TrendMicroApex import servers_list_command
    requests_mock.get(f'{MOCK_URL}/WebApp/API/ServerResource/ProductServers', json=MOCK_SERVERS_LIST)
    mocker.patch.object(client, 'create_jwt_token', return_value="fake_token")

    response = servers_list_command(client, {})

    output = response.outputs
    assert output
    assert len(output) == 3
    assert isinstance(output[0].get('ip_address_list'), list)  # Check that the list parse was successful
    assert response.outputs_prefix == 'TrendMicroApex.Server'


def test_agents_list_command(requests_mock, mocker):
    """ Unit test
    Given
        - agents_list command
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.

    Then
        Validate the content of the CommandResult
    """
    from TrendMicroApex import agents_list_command
    requests_mock.get(f'{MOCK_URL}/WebApp/API/AgentResource/ProductAgents', json=MOCK_AGENTS_LIST)
    mocker.patch.object(client, 'create_jwt_token', return_value="fake_token")

    response = agents_list_command(client, {})

    outputs = response.outputs
    assert outputs
    assert len(outputs) == 1
    assert isinstance(outputs[0].get('ip_address_list'), list)  # Check that the list parse was successful
    assert response.outputs_prefix == 'TrendMicroApex.Agent'


def test_endpoint_sensors_list_command(requests_mock, mocker):
    """ Unit test
    Given
        - endpoint_sensors_list command
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.

    Then
        Validate the content of the CommandResult
    """
    from TrendMicroApex import endpoint_sensors_list_command
    requests_mock.put(f'{MOCK_URL}/WebApp/OSCE_iES/OsceIes/ApiEntry', json=MOCK_SENSORS_LIST)
    mocker.patch.object(client, 'create_jwt_token', return_value="fake_token")

    response = endpoint_sensors_list_command(client, {})

    mock_output = [
        {
            "agentGuid": "b59e624c-2cf0-4180-83d7-e08abbf9ad54",
            "serverGuid": "B220EB61-6240-44B4-9B94-4AC3F22E6A62",
            "machineName": "TRENDMICROAPEX-",
            "isImportant": False,
            "isOnline": False,
            "ip": "10.128.0.11",
            "machineGuid": "3C8DFD21-6175-4AE6-8D51-6DB3186732B2",
            "machineType": "Server",
            "machineLabels": None,
            "machineOS": "Windows Server 2019",
            "isolateStatus": 0,
            "isEnable": True,
            "userName": "TRENDMICROAPEX-\\admin",
            "userGuid": "DC15EA904-03CC-E3A2-9CC0-BA57D814772",
            "productType": 15
        }
    ]

    agents_list = response.outputs

    assert agents_list == mock_output
    assert response.outputs_prefix == 'TrendMicroApex.EndpointSensorSecurityAgent'


def test_create_historical_investigation(requests_mock, mocker):
    """ Unit test
    Given
        - create_historical_investigation command
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.

    Then
        Validate the content of the CommandResult
    """
    from TrendMicroApex import create_historical_investigation
    requests_mock.post(f'{MOCK_URL}/WebApp/OSCE_iES/OsceIes/ApiEntry', json=MOCK_HISTORICAL_INVESTIGATION)
    mocker.patch.object(client, 'create_jwt_token', return_value="fake_token")
    args = {
        'operator': 'OR'
    }
    response = create_historical_investigation(client, args)

    outputs = response.outputs
    assert outputs
    assert outputs.get('taskId')
    assert 'Meta' not in outputs  # check that unnecessary fields was removed from the response
    assert 'The historical investigation was created successfully' in response.readable_output
    assert response.outputs_prefix == 'TrendMicroApex.HistoricalInvestigation'


def test_investigation_result_list_command(requests_mock, mocker):
    """ Unit test
    Given
        - investigation_result_list_command command
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.

    Then
        Validate the content of the CommandResult
    """
    from TrendMicroApex import investigation_result_list_command
    requests_mock.put(f'{MOCK_URL}/WebApp/OSCE_iES/OsceIes/ApiEntry', json=MOCK_RESULT_LIST)
    mocker.patch.object(client, 'create_jwt_token', return_value="fake_token")
    args = {
        'scan_type': 'YARA rule file'
    }
    response = investigation_result_list_command(client, args)

    outputs = response.outputs
    assert outputs
    assert len(outputs) == 2
    assert 'Meta' not in outputs  # check that unnecessary fields was removed from the response
    assert 'Investigation result list' in response.readable_output
    assert outputs[0].get('submitTime') == '2020-07-26T17:02:03+00:00'  # check that time values were parsed
    assert response.outputs_prefix == 'TrendMicroApex.InvestigationResult'


def test_investigation_result_list_command(requests_mock, mocker):
    """ Unit test
    Given
        - investigation_result_list_command command
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.

    Then
        Validate the content of the CommandResult
    """
    from TrendMicroApex import investigation_result_list_command
    requests_mock.put(f'{MOCK_URL}/WebApp/OSCE_iES/OsceIes/ApiEntry', json=MOCK_RESULT_LIST)
    mocker.patch.object(client, 'create_jwt_token', return_value="fake_token")
    args = {
        'scan_type': 'YARA rule file'
    }
    response = investigation_result_list_command(client, args)

    outputs = response.outputs
    assert outputs
    assert len(outputs) == 2
    assert 'Meta' not in outputs  # check that unnecessary fields was removed from the response
    assert 'Investigation result list' in response.readable_output
    assert outputs[0].get('submitTime') == '2020-07-26T17:02:03+00:00'  # check that time values were parsed
    assert response.outputs_prefix == 'TrendMicroApex.InvestigationResult'