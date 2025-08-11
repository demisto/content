import json
import os

import demistomock as demisto
import pytest
from TrendMicroApex import Client, list_logs_command

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
    """Unit test
    Given
        - logs_list command
        - command args - log_type
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.
    Then
        Validate the content of the CommandResult
    """
    MOCK_LOGS_LIST = load_test_data("./test_data/logs_list_command_mock.json")
    requests_mock.get(
        f"{MOCK_URL}/WebApp/api/v1/logs/web_security?output_format=1&page_token=0&since_time=0", json=MOCK_LOGS_LIST
    )
    args = {"log_type": "Web Violation"}
    mocker.patch.object(Client, "create_jwt_token", return_value="fake_token")

    response = list_logs_command(client, args)
    outputs = response.outputs
    assert outputs
    assert len(outputs) == 5
    assert outputs[0].get("EventID")  # check that the cef parse was successful
    assert "Trend Micro Apex One - Web Violation Logs" in response.readable_output
    assert response.outputs_prefix == "TrendMicroApex.Log"


def test_udso_file_add_command(requests_mock, mocker):
    """Unit test
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
    MOCK_ADD_FILE = load_test_data("./test_data/add_file_command_mock.json")
    from TrendMicroApex import udso_file_add_command

    requests_mock.put(f"{MOCK_URL}/WebApp/api/SuspiciousObjectResource/FileUDSO", json=MOCK_ADD_FILE)
    mocker.patch.object(client, "create_jwt_token", return_value="fake_token")

    file_path = os.path.join("test_data", "file_example.txt")
    mocker.patch.object(demisto, "getFilePath", return_value={"path": file_path, "name": "file_example"})

    args = {"file_scan_action": "Log", "note": "example_note", "entry_id": "fake_entry_id"}

    response = udso_file_add_command(client, args)
    assert '### The file "file_example" was added to the UDSO list successfully' in response.readable_output


def test_servers_list_command(requests_mock, mocker):
    """Unit test
    Given
        - managed_servers_list command
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.

    Then
        Validate the content of the CommandResult
    """
    MOCK_SERVERS_LIST = load_test_data("./test_data/servers_list_command_mock.json")
    from TrendMicroApex import servers_list_command

    requests_mock.get(f"{MOCK_URL}/WebApp/API/ServerResource/ProductServers", json=MOCK_SERVERS_LIST)
    mocker.patch.object(client, "create_jwt_token", return_value="fake_token")

    response = servers_list_command(client, {})

    output = response.outputs
    assert output
    assert len(output) == 3
    assert isinstance(output[0].get("ip_address_list"), list)  # Check that the list parse was successful
    assert response.outputs_prefix == "TrendMicroApex.Server"


def test_agents_list_command(requests_mock, mocker):
    """Unit test
    Given
        - agents_list command
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.

    Then
        Validate the content of the CommandResult
    """
    MOCK_AGENTS_LIST = load_test_data("./test_data/agent_list_command_mock.json")
    from TrendMicroApex import agents_list_command

    requests_mock.get(f"{MOCK_URL}/WebApp/API/AgentResource/ProductAgents", json=MOCK_AGENTS_LIST)
    mocker.patch.object(client, "create_jwt_token", return_value="fake_token")

    response = agents_list_command(client, {})

    outputs = response.outputs
    assert outputs
    assert len(outputs) == 1
    assert isinstance(outputs[0].get("ip_address_list"), list)  # Check that the list parse was successful
    assert response.outputs_prefix == "TrendMicroApex.Agent"


def test_endpoint_sensors_list_command(requests_mock, mocker):
    """Unit test
    Given
        - endpoint_sensors_list command
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.

    Then
        Validate the content of the CommandResult
    """
    MOCK_SENSORS_LIST = load_test_data("./test_data/sensors_list_command_mock.json")
    from TrendMicroApex import endpoint_sensors_list_command

    requests_mock.put(f"{MOCK_URL}/WebApp/OSCE_iES/OsceIes/ApiEntry", json=MOCK_SENSORS_LIST)
    mocker.patch.object(client, "create_jwt_token", return_value="fake_token")

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
            "productType": 15,
        }
    ]

    agents_list = response.outputs

    assert agents_list == mock_output
    assert response.outputs_prefix == "TrendMicroApex.EndpointSensorSecurityAgent"


def test_create_historical_investigation(requests_mock, mocker):
    """Unit test
    Given
        - create_historical_investigation command
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.

    Then
        Validate the content of the CommandResult
    """
    MOCK_HISTORICAL_INVESTIGATION = load_test_data("./test_data/historical_investigation_command_mock.json")
    from TrendMicroApex import create_historical_investigation

    requests_mock.post(f"{MOCK_URL}/WebApp/OSCE_iES/OsceIes/ApiEntry", json=MOCK_HISTORICAL_INVESTIGATION)
    mocker.patch.object(client, "create_jwt_token", return_value="fake_token")
    args = {"operator": "OR"}
    response = create_historical_investigation(client, args)

    outputs = response.outputs
    assert outputs
    assert outputs.get("taskId")
    assert "Meta" not in outputs  # check that unnecessary fields was removed from the response
    assert "The historical investigation was created successfully" in response.readable_output
    assert response.outputs_prefix == "TrendMicroApex.HistoricalInvestigation"


def test_investigation_result_list_command(requests_mock, mocker):
    """Unit test
    Given
        - investigation_result_list_command command
    When
        - mock the server response to http_request.
        - mock the response to the create_jwt_token method.

    Then
        Validate the content of the CommandResult
    """
    MOCK_RESULT_LIST = load_test_data("./test_data/result_list_command_mock.json")
    from TrendMicroApex import investigation_result_list_command

    requests_mock.put(f"{MOCK_URL}/WebApp/OSCE_iES/OsceIes/ApiEntry", json=MOCK_RESULT_LIST)
    mocker.patch.object(client, "create_jwt_token", return_value="fake_token")
    args = {"scan_type": "YARA rule file"}
    response = investigation_result_list_command(client, args)

    outputs = response.outputs
    assert outputs
    assert len(outputs) == 2
    assert "Meta" not in outputs  # check that unnecessary fields was removed from the response
    assert "Investigation result list" in response.readable_output
    assert outputs[0].get("status") == "Complete"
    assert outputs[0].get("submitTime") == "2020-07-26T17:02:03+00:00"  # check that time values were parsed
    assert response.outputs_prefix == "TrendMicroApex.InvestigationResult"


""" HELPER FUNCTIONS"""

SINCE_TIME_INPUTS = [
    ("2020-06-21T08:00:00Z", True),
    ("2020-06-21T08:00:00", False),  # missing 'Z' at the end
    ("Jun 21 2020 08:00:00 GMT+00:00", True),
    ("Jun 21 2020 08:00:00 GMT+08:00", False),  # not utc since GMT is +8
]


@pytest.mark.parametrize("since_time, is_valid", SINCE_TIME_INPUTS)
def test_verify_format_and_convert_to_timestamp(since_time, is_valid):
    """Unit test
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
    """Unit test
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
        },
    ]

    expected_list = [
        {
            "scanSummaryId": 2,
            "scanSummaryGuid": "80e5f8b4-3419-455d-99ce-9699ead90781",
            "status": "Complete",
            "statusForUI": "Complete",
            "scanType": "YARA rule file",
            "submitTime": "2020-07-26T17:02:03+00:00",
            "finishTime": "2020-07-27T17:04:03+00:00",
            "name": "Test1",
        },
        {
            "scanSummaryId": 1,
            "scanSummaryGuid": "5023de82-464e-4694-91a3-f27a48b42ba4",
            "status": "Complete",
            "statusForUI": "Complete",
            "scanType": "YARA rule file",
            "submitTime": "2020-07-26T14:14:37+00:00",
            "finishTime": "2020-07-27T14:15:03+00:00",
            "triggerTime": "2020-07-26T14:15:02+00:00",
            "name": "Test2",
        },
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

    args = {"type": "file", "content_filter": "test"}

    expected_response = {"Data": [{"content": "test1", "type": "file"}, {"content": "test2", "type": "file"}]}

    mocker.patch.object(client, "udso_list", return_value=expected_response)

    result = udso_list_command(client, args)

    assert result.outputs == {
        "TrendMicroApex.UDSO(val.content == obj.content)": expected_response["Data"],
        "TrendMicroApex.USDO(val.content == obj.content)": expected_response["Data"],
    }
    assert result.readable_output == "### Apex One UDSO List\n|content|type|\n|---|---|\n| test1 | file |\n| test2 | file |\n"
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
    expected_response = {"success": True}

    mocker.patch.object(Client, "udso_delete", return_value=expected_response)

    args = {"type": "test_type", "content": "test_content"}

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

    args = {"type": "hash", "content": "1234567890abcdef", "scan_action": "clean"}
    expected_output = '### UDSO "1234567890abcdef" of type "hash" was added successfully with scan action "clean"'

    mocker.patch.object(client, "udso_add", return_value={"success": True})

    result = udso_add_command(client, args)

    assert result.readable_output == expected_output
    assert result.raw_response == {"success": True}


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

    args = {"entity_id": "12345"}

    mocker.patch.object(client, "prodagent_isolate", return_value={"result_content": [{"agentGuid": "12345"}]})

    result = prodagent_isolate_command(client, args)

    assert result.outputs_prefix == "TrendMicroApex.ProductAgent"
    assert result.outputs == [{"agentGuid": "12345"}]
    assert result.readable_output == "### Apex One ProductAgent Isolate\n|agentGuid|\n|---|\n| 12345 |\n"


def test_prodagent_restore_command(mocker):
    """
    Given:
    - The entity_id argument is provided.

    When:
    - Calling the prodagent_restore_command function.

    Then:
    - Ensure the function returns a CommandResults object with the expected outputs.
    """
    from TrendMicroApex import prodagent_restore_command

    args = {"entity_id": "12345"}

    mocker.patch.object(client, "prodagent_restore", return_value={"result_content": [{"agentGuid": "12345"}]})

    result = prodagent_restore_command(client, args)

    assert result.outputs_prefix == "TrendMicroApex.ProductAgent"
    assert result.outputs == [{"agentGuid": "12345"}]
    assert result.readable_output == "### Apex One ProductAgent Restore\n|agentGuid|\n|---|\n| 12345 |\n"


def test_remove_unnecessary_fields_from_response():
    from TrendMicroApex import Client
    response = {
        "Data": {
            "some_key": "some_value",
            "FeatureCtrl": "test",
            "Meta": "test",
            "PermissionCtrl": "test",
            "SystemCtrl": "test",
        }
    }
    Client.remove_unnecessary_fields_from_response(response)
    assert "FeatureCtrl" not in response.get("Data", {})
    assert "Meta" not in response.get("Data", {})
    assert "PermissionCtrl" not in response.get("Data", {})
    assert "SystemCtrl" not in response.get("Data", {})
    assert "some_key" in response.get("Data", {})


def test_build_query_string():
    """
    Given:
        - Different combinations of query parameters.
    When:
        - Calling the build_query_string function.
    Then:
        - Ensure the generated query string is correct.
    """
    from TrendMicroApex import Client

    # Test case 1: All parameters provided
    query = Client.build_query_string(
        entity_id="guid",
        ip_address="1.1.1.1",
        mac_address="00-00-00-00-00-00",
        host_name="hostname",
        product="product",
        managing_server_id="server_guid",
    )
    assert "m_szEntityId=guid" in query
    assert "m_szIp=1.1.1.1" in query
    assert "m_szMac=00-00-00-00-00-00" in query
    assert "m_szHostName=hostname" in query
    assert "m_szProduct=product" in query
    assert "m_szManagingServerId=server_guid" in query

    # Test case 2: Some parameters provided
    query = Client.build_query_string(ip_address="1.1.1.1", host_name="hostname")
    assert "m_szIp=1.1.1.1" in query
    assert "m_szHostName=hostname" in query
    assert "m_szEntityId" not in query

    # Test case 3: No parameters provided
    query = Client.build_query_string()
    assert query == ""


@pytest.mark.parametrize(
    "http_method, api_path, headers, request_body, expected_checksum",
    [
        # Test case 1: Simple GET request with no body
        (
            "GET",
            "/WebApp/API/AgentResource/ProductAgents",
            {"api-key": "some_key"},
            None,
            "sF8xroyz4J3/KVM+EwYKlLpFRXUn2dY3DUvD9k/p0aM=",
        ),
        # Test case 2: POST request with a dictionary body
        (
            "POST",
            "/WebApp/api/SuspiciousObjects/UserDefinedSO",
            {"Content-Type": "application/json", "api-version": "2.0"},
            {"param": "value", "key": "data"},
            "SV8xGz/F1LVVcrar2ePu21pGfP3pZpL3e1Qj/xZ/E2c=",
        ),
        # Test case 3: POST request with a JSON string body
        (
            "POST",
            "/WebApp/api/SuspiciousObjects/UserDefinedSO",
            {"Content-Type": "application/json", "api-version": "2.0"},
            '{"param":"value","key":"data"}',
            "SV8xGz/F1LVVcrar2ePu21pGfP3pZpL3e1Qj/xZ/E2c=",
        ),
        # Test case 4: Request with mixed headers
        (
            "PUT",
            "/some/path",
            {"api-key": "key1", "X-Custom-Header": "ignore", "API-SECRET": "secret1"},
            None,
            "Ld1TzWfC8EbUeJ8dD+pW/cWpXpY8aZ7cZ7e8b9B0D1E=",
        ),
        # Test case 5: Request with URL query parameters
        (
            "GET",
            "/api/v1/resource?param1=val1&param2=val2",
            {"api-key": "query_key"},
            None,
            "R/fJz/d9C5aJ6fWpXlZ7e8a9B0D1E/cWpXpY8aZ7c=",
        ),
    ],
)
def test_create_checksum(http_method, api_path, headers, request_body, expected_checksum):
    """
    Given:
        - Different HTTP methods, API paths, headers, and request bodies.
    When:
        - Calling the __create_checksum static method.
    Then:
        - Ensure the generated checksum matches the expected value.
    """
    # Add a dummy import for the missing types

    # Call the static method
    checksum = Client.__create_checksum(http_method, api_path, headers, request_body)

    # Assert the result
    assert checksum == expected_checksum
