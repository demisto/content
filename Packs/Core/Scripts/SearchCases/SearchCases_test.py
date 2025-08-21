import pytest
from SearchCases import Client, extract_ids, get_cases_with_extra_data


def test_get_extra_data_for_case_id_success(mocker):
    """
    Given:
    - A valid case_id and issues_limit
    When:
    - Executing get_extra_data_for_case_id function
    Then:
    - Ensure _http_request was called with correct parameters
    - Ensure the correct response is returned
    """
    # Mock input arguments
    case_id = "test_case_123"
    issues_limit = 500
    
    # Mock return value
    mock_response = {
        "reply": {
            "alerts": {"data": [{"alert_id": "alert_1"}, {"alert_id": "alert_2"}]},
            "network_artifacts": [{"artifact": "network_data"}],
            "file_artifacts": [{"artifact": "file_data"}]
        }
    }
    
    # Create client instance and mock _http_request
    client = Client(base_url="/api/webapp/public_api/v1", proxy=False, verify=True, headers={}, timeout=120)
    mock_http_request = mocker.patch.object(client, '_http_request', return_value=mock_response)
    mock_debug = mocker.patch("SearchCases.demisto.debug")
    
    # Execute function
    result = client.get_extra_data_for_case_id(case_id, issues_limit)
    
    # Assertions
    assert mock_http_request.call_count == 1
    expected_request_data = {
        "incident_id": case_id,
        "alerts_limit": issues_limit,
        "full_alert_fields": True
    }
    mock_http_request.assert_called_with(
        method="POST",
        url_suffix="/incidents/get_incident_extra_data/",
        json_data={"request_data": expected_request_data},
        headers=client._headers,
        timeout=client.timeout
    )
    assert result == mock_response["reply"]
    assert mock_debug.call_count == 2


def test_get_extra_data_for_case_id_empty_response(mocker):
    """
    Given:
    - A valid case_id but API returns empty response
    When:
    - Executing get_extra_data_for_case_id function
    Then:
    - Ensure empty dict is returned when reply key is missing
    """
    # Mock input arguments
    case_id = "test_case_456"
    
    # Mock return value without reply key
    mock_response = {}
    
    # Create client instance and mock _http_request
    client = Client(base_url="/api/webapp/public_api/v1", proxy=False, verify=True, headers={}, timeout=120)
    mock_http_request = mocker.patch.object(client, '_http_request', return_value=mock_response)
    mocker.patch("SearchCases.demisto.debug")
    
    # Execute function
    result = client.get_extra_data_for_case_id(case_id)
    
    # Assertions
    assert mock_http_request.call_count == 1
    assert result == {}


def test_extract_ids_with_dict_input():
    """
    Given:
    - A dictionary with the specified field_name
    When:
    - Executing extract_ids function
    Then:
    - Ensure correct list with single ID is returned
    """
    # Mock input
    command_res = {"alert_id": "test_alert_123", "other_field": "value"}
    field_name = "alert_id"
    
    # Execute function
    result = extract_ids(command_res, field_name)
    
    # Assertions
    assert result == ["test_alert_123"]


def test_extract_ids_with_dict_missing_field():
    """
    Given:
    - A dictionary without the specified field_name
    When:
    - Executing extract_ids function
    Then:
    - Ensure empty list is returned
    """
    # Mock input
    command_res = {"other_field": "value", "another_field": "another_value"}
    field_name = "alert_id"
    
    # Execute function
    result = extract_ids(command_res, field_name)
    
    # Assertions
    assert result == []


def test_extract_ids_with_list_input():
    """
    Given:
    - A list of dictionaries with the specified field_name
    When:
    - Executing extract_ids function
    Then:
    - Ensure correct list of IDs is returned
    """
    # Mock input
    command_res = [
        {"alert_id": "alert_1", "other_field": "value1"},
        {"alert_id": "alert_2", "other_field": "value2"},
        {"different_field": "value3"},  # This should be skipped
        {"alert_id": "alert_3"}
    ]
    field_name = "alert_id"
    
    # Execute function
    result = extract_ids(command_res, field_name)
    
    # Assertions
    assert result == ["alert_1", "alert_2", "alert_3"]


def test_extract_ids_with_empty_list():
    """
    Given:
    - An empty list
    When:
    - Executing extract_ids function
    Then:
    - Ensure empty list is returned
    """
    # Mock input
    command_res = []
    field_name = "alert_id"
    
    # Execute function
    result = extract_ids(command_res, field_name)
    
    # Assertions
    assert result == []


def test_extract_ids_with_none_input():
    """
    Given:
    - None as input
    When:
    - Executing extract_ids function
    Then:
    - Ensure empty list is returned
    """
    # Mock input
    command_res = None
    field_name = "alert_id"
    
    # Execute function
    result = extract_ids(command_res, field_name)
    
    # Assertions
    assert result == []


def test_get_cases_with_extra_data_success(mocker):
    """
    Given:
    - Valid client and args with cases data
    When:
    - Executing get_cases_with_extra_data function
    Then:
    - Ensure execute_command was called with correct args
    - Ensure client.get_extra_data_for_case_id was called for each case
    - Ensure cases are enriched with extra data correctly
    """
    # Mock input arguments
    args = {"alerts_limit": "500", "status": "open"}
    
    # Mock cases data from core-get-cases
    mock_cases = [
        {"case_id": "case_1", "name": "Test Case 1"},
        {"case_id": "case_2", "name": "Test Case 2"}
    ]
    
    # Mock extra data responses
    mock_extra_data_1 = {
        "alerts": {"data": [{"alert_id": "alert_1"}, {"alert_id": "alert_2"}]},
        "network_artifacts": [{"network": "artifact_1"}],
        "file_artifacts": [{"file": "artifact_1"}]
    }
    mock_extra_data_2 = {
        "alerts": {"data": [{"alert_id": "alert_3"}]},
        "network_artifacts": [{"network": "artifact_2"}],
        "file_artifacts": [{"file": "artifact_2"}]
    }
    
    # Create client instance and mock methods
    client = Client(base_url="/api/webapp/public_api/v1", proxy=False, verify=True, headers={}, timeout=120)
    mock_execute_command = mocker.patch("SearchCases.execute_command", return_value=mock_cases)
    mock_get_extra_data = mocker.patch.object(
        client, 
        'get_extra_data_for_case_id', 
        side_effect=[mock_extra_data_1, mock_extra_data_2]
    )
    mocker.patch("SearchCases.demisto.debug")
    
    # Execute function
    result = get_cases_with_extra_data(client, args)
    
    # Assertions
    assert mock_execute_command.call_count == 1
    mock_execute_command.assert_called_with("core-get-cases", args)
    
    assert mock_get_extra_data.call_count == 2
    mock_get_extra_data.assert_any_call("case_1")
    mock_get_extra_data.assert_any_call("case_2")
    
    assert len(result) == 2
    
    # Check first case enrichment
    assert result[0]["case_id"] == "case_1"
    assert result[0]["issue_ids"] == ["alert_1", "alert_2"]
    assert result[0]["network_artifacts"] == [{"network": "artifact_1"}]
    assert result[0]["file_artifacts"] == [{"file": "artifact_1"}]
    
    # Check second case enrichment
    assert result[1]["case_id"] == "case_2"
    assert result[1]["issue_ids"] == ["alert_3"]
    assert result[1]["network_artifacts"] == [{"network": "artifact_2"}]
    assert result[1]["file_artifacts"] == [{"file": "artifact_2"}]


def test_get_cases_with_extra_data_with_alerts_limit_cap(mocker):
    """
    Given:
    - Args with alerts_limit exceeding 1000
    When:
    - Executing get_cases_with_extra_data function
    Then:
    - Ensure alerts_limit is capped at 1000
    """
    # Mock input arguments with high alerts_limit
    args = {"alerts_limit": "1500"}
    
    # Mock cases data
    mock_cases = [{"case_id": "case_1", "name": "Test Case 1"}]
    mock_extra_data = {
        "alerts": {"data": [{"alert_id": "alert_1"}]},
        "network_artifacts": [],
        "file_artifacts": []
    }
    
    # Create client and mock methods
    client = Client(base_url="/api/webapp/public_api/v1", proxy=False, verify=True, headers={}, timeout=120)
    mocker.patch("SearchCases.execute_command", return_value=mock_cases)
    mock_get_extra_data = mocker.patch.object(client, 'get_extra_data_for_case_id', return_value=mock_extra_data)
    mocker.patch("SearchCases.demisto.debug")
    
    # Execute function
    get_cases_with_extra_data(client, args)
    
    # Assertions - the get_extra_data_for_case_id should be called with default 1000 limit
    mock_get_extra_data.assert_called_with("case_1")


def test_get_cases_with_extra_data_skip_cases_without_id(mocker):
    """
    Given:
    - Cases data where some cases don't have case_id
    When:
    - Executing get_cases_with_extra_data function
    Then:
    - Ensure cases without case_id are skipped
    - Ensure only valid cases are processed
    """
    # Mock input arguments
    args = {"alerts_limit": "100"}
    
    # Mock cases data with missing case_id
    mock_cases = [
        {"case_id": "case_1", "name": "Valid Case 1"},
        {"name": "Invalid Case - No ID"},  # Missing case_id
        {"case_id": "", "name": "Invalid Case - Empty ID"},  # Empty case_id
        {"case_id": "case_2", "name": "Valid Case 2"}
    ]
    
    # Mock extra data response
    mock_extra_data = {
        "alerts": {"data": []},
        "network_artifacts": [],
        "file_artifacts": []
    }
    
    # Create client and mock methods
    client = Client(base_url="/api/webapp/public_api/v1", proxy=False, verify=True, headers={}, timeout=120)
    mocker.patch("SearchCases.execute_command", return_value=mock_cases)
    mock_get_extra_data = mocker.patch.object(client, 'get_extra_data_for_case_id', return_value=mock_extra_data)
    mocker.patch("SearchCases.demisto.debug")
    
    # Execute function
    result = get_cases_with_extra_data(client, args)
    
    # Assertions
    assert len(result) == 2  # Only 2 valid cases should be processed
    assert mock_get_extra_data.call_count == 2
    assert result[0]["case_id"] == "case_1"
    assert result[1]["case_id"] == "case_2"


def test_get_cases_with_extra_data_empty_cases(mocker):
    """
    Given:
    - Empty cases result from core-get-cases
    When:
    - Executing get_cases_with_extra_data function
    Then:
    - Ensure empty list is returned
    - Ensure no extra data calls are made
    """
    # Mock input arguments
    args = {"status": "closed"}
    
    # Create client and mock methods
    client = Client(base_url="/api/webapp/public_api/v1", proxy=False, verify=True, headers={}, timeout=120)
    mock_execute_command = mocker.patch("SearchCases.execute_command", return_value=[])
    mock_get_extra_data = mocker.patch.object(client, 'get_extra_data_for_case_id')
    mocker.patch("SearchCases.demisto.debug")
    
    # Execute function
    result = get_cases_with_extra_data(client, args)
    
    # Assertions
    assert mock_execute_command.call_count == 1
    assert mock_get_extra_data.call_count == 0
    assert result == []
