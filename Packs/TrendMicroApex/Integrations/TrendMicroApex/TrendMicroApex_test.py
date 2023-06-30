import json
import os
import demistomock as demisto
import pytest
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
    MOCK_LOGS_LIST = load_test_data('./test_data/logs_list_command_mock.json')
    requests_mock.get(f'{MOCK_URL}/WebApp/api/v1/logs/web_security?output_format=1&page_token=0&since_time=0',
                      json=MOCK_LOGS_LIST)
    args = {
        'log_type': 'Web Violation'
    }
    mocker.patch.object(Client, 'create_jwt_token', return_value="fake_token")

    response = list_logs_command(client, args)
    outputs = response.outputs
    assert outputs
    assert len(outputs) == 5
    assert outputs[0].get('EventID')  # check that the cef parse was successful
    assert 'Trend Micro Apex One - Web Violation Logs' in response.readable_output
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
    MOCK_ADD_FILE = load_test_data('./test_data/add_file_command_mock.json')
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
    MOCK_SERVERS_LIST = load_test_data('./test_data/servers_list_command_mock.json')
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
    MOCK_AGENTS_LIST = load_test_data('./test_data/agent_list_command_mock.json')
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
    MOCK_SENSORS_LIST = load_test_data('./test_data/sensors_list_command_mock.json')
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
            "ip": "8.8.8.8",
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
    MOCK_HISTORICAL_INVESTIGATION = load_test_data('./test_data/historical_investigation_command_mock.json')
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
    MOCK_RESULT_LIST = load_test_data('./test_data/result_list_command_mock.json')
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
    assert outputs[0].get('status') == 'Complete'
    assert outputs[0].get('submitTime') == '2020-07-26T17:02:03+00:00'  # check that time values were parsed
    assert response.outputs_prefix == 'TrendMicroApex.InvestigationResult'


''' HELPER FUNCTIONS'''

SINCE_TIME_INPUTS = [
    ('2020-06-21T08:00:00Z', True),
    ('2020-06-21T08:00:00', False),  # missing 'Z' at the end
    ('Jun 21 2020 08:00:00 GMT+00:00', True),
    ('Jun 21 2020 08:00:00 GMT+08:00', False)  # not utc since GMT is +8
]


@pytest.mark.parametrize('since_time, is_valid', SINCE_TIME_INPUTS)
def test_verify_format_and_convert_to_timestamp(since_time, is_valid):
    """ Unit test
    Given
        - verify_format_and_convert_to_timestamp helper function
    When
        - There are two allowed date formats

    Then
        - Validate the timestamp parsing is successful
        - Validate that error is thrown if needed
    """
    if is_valid:
        timestamp = Client.verify_format_and_convert_to_timestamp(since_time)
        assert timestamp == 1592726400
    else:
        try:
            _ = Client.verify_format_and_convert_to_timestamp(since_time)
        except ValueError as error:
            assert "'since_time' argument should be in one of the following formats:" in str(error)


def test_convert_timestamps_and_scan_type_to_readable():
    """ Unit test
    Given
        - convert_timestamps_and_scan_type_to_readable helper function
    When
        - function arg is a list containing timestamp values

    Then
        - Validate all the timestamp values are being successful parsed
        - Validate there are no other fields that changed.
    """
    test_list = [
        {
            "scanSummaryId": 2,
            "scanSummaryGuid": "80e5f8b4-3419-455d-99ce-9699ead90781",
            "status": 3,
            "statusForUI": 3,
            "scanType": 2,
            "submitTime": 1595782923,
            "finishTime": 1595869443,
            "name": "Test1",
        },
        {
            "scanSummaryId": 1,
            "scanSummaryGuid": "5023de82-464e-4694-91a3-f27a48b42ba4",
            "status": 3,
            "statusForUI": 3,
            "scanType": 2,
            "submitTime": 1595772877,
            "finishTime": 1595859303,
            "triggerTime": 1595772902,
            "name": "Test2",
        }
    ]

    expected_list = [
        {
            "scanSummaryId": 2,
            "scanSummaryGuid": "80e5f8b4-3419-455d-99ce-9699ead90781",
            "status": "Complete",
            "statusForUI": "Complete",
            "scanType": "YARA rule file",
            "submitTime": '2020-07-26T17:02:03+00:00',
            "finishTime": '2020-07-27T17:04:03+00:00',
            "name": "Test1",
        },
        {
            "scanSummaryId": 1,
            "scanSummaryGuid": "5023de82-464e-4694-91a3-f27a48b42ba4",
            "status": "Complete",
            "statusForUI": "Complete",
            "scanType": "YARA rule file",
            "submitTime": '2020-07-26T14:14:37+00:00',
            "finishTime": '2020-07-27T14:15:03+00:00',
            "triggerTime": '2020-07-26T14:15:02+00:00',
            "name": "Test2",
        }
    ]
    result_list = Client.convert_timestamps_and_scan_type_to_readable(test_list)
    assert expected_list == result_list


def test_udso_list_command(mocker):
    """
    Given:
    - Valid input parameters.

    When:
    - Calling udso_list_command function.

    Then:
    - Ensure the function returns a valid response.
    """
    from TrendMicroApex import udso_list_command
    args = {'type': 'file', 'content_filter': 'test'}

    expected_response = {
        'Data': [
            {'content': 'test1', 'type': 'file'},
            {'content': 'test2', 'type': 'file'}
        ]
    }

    mocker.patch.object(client, 'udso_list', return_value=expected_response)

    result = udso_list_command(client, args)

    assert result.outputs == {
        'TrendMicroApex.UDSO(val.content == obj.content)': expected_response['Data'],
        'TrendMicroApex.USDO(val.content == obj.content)': expected_response['Data']
    }
    assert result.readable_output == '### Apex One UDSO List\n|content|type|\n|---|---|\n| test1 | file |\n| test2 | file |\n'
    assert result.raw_response == expected_response


def test_udso_delete_command(mocker):
    """
    Given:
    - A client object
    - A dictionary containing the UDSO type and content to delete

    When:
    - Calling the udso_delete_command function

    Then:
    - Ensure the function successfully deletes the UDSO of the specified type and content
    - Ensure the CommandResults object contains the expected readable output and raw response
    """
    from TrendMicroApex import udso_delete_command
    expected_output = '### UDSO "test_content" of type "test_type" was deleted successfully'
    expected_response = {'success': True}

    mocker.patch.object(Client, 'udso_delete', return_value=expected_response)

    args = {'type': 'test_type', 'content': 'test_content'}

    result = udso_delete_command(client, args)

    assert result.readable_output == expected_output
    assert result.raw_response == expected_response


def test_udso_add_command(mocker):
    """
    Given:
    - All required arguments are provided.

    When:
    - Calling udso_add_command function.

    Then:
    - Ensure the function returns a CommandResults object with the expected readable output and raw response.
    """
    from TrendMicroApex import udso_add_command
    args = {
        'type': 'hash',
        'content': '1234567890abcdef',
        'scan_action': 'clean'
    }
    expected_output = '### UDSO "1234567890abcdef" of type "hash" was added successfully with scan action "clean"'

    mocker.patch.object(client, 'udso_add', return_value={'success': True})

    result = udso_add_command(client, args)

    assert result.readable_output == expected_output
    assert result.raw_response == {'success': True}


def test_prodagent_isolate_command(mocker):
    """
    Given:
    - The entity_id argument is provided.

    When:
    - Calling the prodagent_isolate_command function.

    Then:
    - Ensure the function returns a CommandResults object with the expected outputs.
    """
    from TrendMicroApex import prodagent_isolate_command
    args = {'entity_id': '12345'}

    mocker.patch.object(client, 'prodagent_isolate', return_value={'result_content': [{'agentGuid': '12345'}]})

    result = prodagent_isolate_command(client, args)

    assert result.outputs_prefix == 'TrendMicroApex.ProductAgent'
    assert result.outputs == [{'agentGuid': '12345'}]
    assert result.readable_output == '### Apex One ProductAgent Isolate\n|agentGuid|\n|---|\n| 12345 |\n'
