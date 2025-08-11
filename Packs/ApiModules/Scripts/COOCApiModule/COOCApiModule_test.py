import json
import pytest
from CommonServerPython import *
from COOCApiModule import CloudTypes, get_cloud_credentials, HealthCheckError, ErrorType, HealthStatus
import demistomock as demisto


def test_get_cloud_credentials_success(mocker):
    """
    Given: A valid cloud type and calling context with required cloud information.
    When: The get_cloud_credentials function is called.
    Then: Function successfully returns the credentials dictionary from the platform API response.
    """

    # Mock context data
    cloud_info = {"connectorID": "test-connector-id", "accountID": "test-account-id", "outpostID": "test-outpost-id"}
    mock_context = {"CloudIntegrationInfo": cloud_info}

    # Mock the demisto functions directly
    mocker.patch.object(demisto, "callingContext", {"context": mock_context})
    mocker.patch.object(demisto, "info")

    # Mock platform API response with credentials
    credentials = {"access_token": "test-access-token", "expiration_time": 1672531200000}
    api_response = {
        "status": 200,
        "data": json.dumps({"data": credentials}),
    }
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    # Call the function
    result = get_cloud_credentials(CloudTypes.AWS.value, account_id="test-account-id")

    # Verify result
    assert result == credentials

    # Verify API call was made with correct parameters
    assert demisto._platformAPICall.called
    call_args = demisto._platformAPICall.call_args[1]
    assert call_args["path"] == "/cts/accounts/token"
    assert call_args["method"] == "POST"
    assert "request_data" in call_args["data"]
    assert call_args["data"]["request_data"]["cloud_type"] == "AWS"


def test_get_cloud_credentials_with_scopes(mocker):
    """
    Given: A valid cloud type and a list of scopes.
    When: The get_cloud_credentials function is called with scopes parameter.
    Then: The scopes are included in the API request.
    """

    # Mock context data
    cloud_info = {"connectorID": "test-connector-id", "accountID": "test-account-id", "outpostID": "test-outpost-id"}
    mock_context = {"CloudIntegrationInfo": cloud_info}
    mocker.patch.object(demisto, "callingContext", {"context": mock_context})
    mocker.patch.object(demisto, "info")

    # Mock platform API response
    credentials = {"access_token": "test-access-token", "expiration_time": 1672531200000}
    api_response = {
        "status": 200,
        "data": json.dumps({"data": credentials}),
    }
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    # Call the function with scopes
    test_scopes = ["scope1", "scope2"]
    result = get_cloud_credentials(CloudTypes.GCP.value, account_id="test-account-id", scopes=test_scopes)

    # Verify result
    assert result == credentials

    # Verify API call was made with correct parameters
    call_args = demisto._platformAPICall.call_args[1]
    request_data = call_args["data"]["request_data"]
    assert request_data["cloud_type"] == "GCP"
    assert request_data["scopes"] == test_scopes


def test_get_cloud_credentials_missing_account_id():
    """
    Given: A cloud type but missing account_id.
    When: The get_cloud_credentials function is called.
    Then: A ValueError is raised with appropriate message.
    """

    with pytest.raises(ValueError) as excinfo:
        get_cloud_credentials(CloudTypes.AWS.value, account_id="")

    assert "Missing AWS Account ID for AWS" in str(excinfo.value)


def test_get_cloud_credentials_api_error(mocker):
    """
    Given: A valid cloud type but the API returns an error.
    When: The get_cloud_credentials function is called.
    Then: A DemistoException is raised with the error details.
    """

    # Mock context data
    cloud_info = {"connectorID": "test-connector-id", "accountID": "test-account-id", "outpostID": "test-outpost-id"}
    mock_context = {"CloudIntegrationInfo": cloud_info}
    mocker.patch.object(demisto, "callingContext", {"context": mock_context})
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    # Mock platform API error response
    api_response = {"status": 400, "data": "Bad request"}
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    # Call the function and expect an exception
    with pytest.raises(DemistoException) as excinfo:
        get_cloud_credentials(CloudTypes.AZURE.value, account_id="test-account-id")

    # Verify exception message
    assert "Failed to get credentials from CTS" in str(excinfo.value)


def test_get_cloud_credentials_parse_error(mocker):
    """
    Given: A valid cloud type but the API returns a malformed response.
    When: The get_cloud_credentials function is called.
    Then: A DemistoException is raised due to parsing failure.
    """

    # Mock context data
    cloud_info = {"connectorID": "test-connector-id", "accountID": "test-account-id", "outpostID": "test-outpost-id"}
    mock_context = {"CloudIntegrationInfo": cloud_info}
    mocker.patch.object(demisto, "callingContext", {"context": mock_context})
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    # Mock platform API with invalid JSON
    api_response = {"status": 200, "data": "Not a valid JSON"}
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    # Call the function and expect an exception
    with pytest.raises(DemistoException) as excinfo:
        get_cloud_credentials(CloudTypes.OCI.value, account_id="test-account-id")

    # Verify exception message
    assert "Failed to get credentials from CTS" in str(excinfo.value)


def test_get_accounts_by_connector_id_with_max_results(mocker):
    """
    Given: A connector_id parameter and max_results parameter.
    When: The get_accounts_by_connector_id function is called with max_results.
    Then: The function returns only the specified number of accounts.
    """

    from COOCApiModule import get_accounts_by_connector_id

    # Mock platform API response with multiple accounts
    api_response = {
        "status": 200,
        "data": json.dumps(
            {
                "values": [
                    {"account_id": "account-1", "account_type": "ACCOUNT"},
                    {"account_id": "account-2", "account_type": "ACCOUNT"},
                    {"account_id": "account-3", "account_type": "ORGANIZATION"},
                ],
                "next_token": "",
            }
        ),
    }
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)
    mocker.patch.object(demisto, "debug")

    # Call the function with max_results=2
    result = get_accounts_by_connector_id(connector_id="test-connector-id", max_results=2)

    # Verify result has only max_results entries
    assert len(result) == 2
    assert result[0]["account_id"] == "account-1"
    assert result[1]["account_id"] == "account-2"


def test_health_check_error_to_dict():
    """
    Given: Parameters for a HealthCheckError.
    When: Creating a HealthCheckError and calling to_dict().
    Then: The returned dictionary contains the expected fields and values.
    """

    # Create HealthCheckError with permission error
    permission_error = HealthCheckError(
        account_id="test-account-id",
        connector_id="test-connector-id",
        message="Permission denied",
        error_type=ErrorType.PERMISSION_ERROR,
    )
    permission_error_dict = permission_error.to_dict()

    # Verify dictionary structure and values
    assert permission_error_dict["account_id"] == "test-account-id"
    assert permission_error_dict["connector_id"] == "test-connector-id"
    assert permission_error_dict["message"] == "Permission denied"
    assert permission_error_dict["error"] == ErrorType.PERMISSION_ERROR
    assert permission_error_dict["classification"] == HealthStatus.WARNING

    # Create HealthCheckError with connectivity error
    connectivity_error = HealthCheckError(
        account_id="test-account-id",
        connector_id="test-connector-id",
        message="Connection failed",
        error_type=ErrorType.CONNECTIVITY_ERROR,
    )
    connectivity_error_dict = connectivity_error.to_dict()

    # Verify classification for different error type
    assert connectivity_error_dict["classification"] == HealthStatus.ERROR


def test_health_check_summarize_no_errors():
    """
    Given: A HealthCheck instance with no errors.
    When: The summarize method is called.
    Then: It returns "ok".
    """
    from COOCApiModule import HealthCheck

    # Create HealthCheck with no errors
    health_check = HealthCheck(connector_id="test-connector-id")

    # Call summarize
    result = health_check.summarize()

    # Verify result
    assert result == HealthStatus.OK


def test_health_check_summarize_with_errors():
    """
    Given: A HealthCheck instance with errors.
    When: The summarize method is called.
    Then: It returns CommandResults with appropriate entry type.
    """
    from COOCApiModule import HealthCheck

    # Create HealthCheck with errors
    health_check = HealthCheck(connector_id="test-connector-id")
    error = HealthCheckError(
        account_id="test-account-id",
        connector_id="test-connector-id",
        message="Test error",
        error_type=ErrorType.PERMISSION_ERROR,
    )
    health_check.error(error)

    # Call summarize
    result = health_check.summarize()

    # Verify result is CommandResults
    assert isinstance(result, CommandResults)
    assert result.entry_type == EntryType.WARNING


def test_check_account(mocker):
    """
    Given: An account, connector_id, shared_creds, and permission check function.
    When: _check_account is called.
    Then: It calls the permission check function with the correct parameters and returns its result.
    """
    from COOCApiModule import _check_account

    # Mock permission check function
    mock_permission_check = mocker.Mock(return_value="permission_check_result")

    # Test with valid account
    account_id = "test-account-id"
    shared_creds = {"access_token": "test-token"}
    result = _check_account(account_id, "test-connector-id", shared_creds, mock_permission_check)

    # Verify permission check was called with correct parameters
    mock_permission_check.assert_called_once_with(shared_creds, "test-account-id", "test-connector-id")
    assert result == "permission_check_result"


def test_check_account_exception(mocker):
    """
    Given: An account, connector_id, shared_creds, and permission check function that raises an exception.
    When: _check_account is called.
    Then: It handles the exception and returns a HealthCheckError.
    """
    from COOCApiModule import _check_account

    # Mock permission check function to raise exception
    mock_permission_check = mocker.Mock(side_effect=Exception("Test error"))
    mocker.patch.object(demisto, "error")

    # Test with exception in permission check
    account_id = "test-account-id"
    shared_creds = {"access_token": "test-token"}
    result = _check_account(account_id, "test-connector-id", shared_creds, mock_permission_check)

    # Verify error was logged and HealthCheckError returned
    assert demisto.error.called
    assert isinstance(result, HealthCheckError)
    assert result.account_id == "test-account-id"
    assert result.connector_id == "test-connector-id"
    assert "Test error" in result.message
    assert result.error_type == ErrorType.INTERNAL_ERROR


def test_run_health_check_no_accounts(mocker):
    """
    Given: A connector_id with no associated accounts.
    When: run_health_check_for_accounts is called.
    Then: It returns "ok" without running any permission checks.
    """
    from COOCApiModule import run_health_check_for_accounts

    # Mock get_accounts_by_connector_id to return empty list
    mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=[])
    mocker.patch.object(demisto, "debug")

    # Call function
    result = run_health_check_for_accounts(connector_id="test-connector-id", cloud_type="AWS", health_check_func=mocker.Mock())

    # Verify results
    assert result == HealthStatus.OK
    assert demisto.debug.called


def test_run_health_check_credentials_failure(mocker):
    """
    Given: A connector_id with accounts but credential retrieval fails.
    When: run_health_check_for_accounts is called.
    Then: It returns CommandResults with connectivity error.
    """
    from COOCApiModule import run_health_check_for_accounts

    # Mock get_accounts_by_connector_id
    accounts = [{"account_id": "account-1"}]
    mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=accounts)

    # Mock get_cloud_credentials to raise exception
    mocker.patch("COOCApiModule.get_cloud_credentials", side_effect=Exception("Credential error"))

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")

    # Mock HealthCheck
    mock_health_check = mocker.MagicMock()
    mock_health_check.summarize.return_value = CommandResults(entry_type=EntryType.ERROR)
    mocker.patch("COOCApiModule.HealthCheck", return_value=mock_health_check)

    # Call function
    run_health_check_for_accounts(connector_id="test-connector-id", cloud_type="AWS", health_check_func=mocker.Mock())

    # Verify error was handled
    assert mock_health_check.error.called
    error_call_args = mock_health_check.error.call_args[0][0]
    assert isinstance(error_call_args, HealthCheckError)
    assert error_call_args.error_type == ErrorType.CONNECTIVITY_ERROR


def test_get_connector_id_success(mocker):
    """
    Given: A calling context with CloudIntegrationInfo containing connectorID.
    When: get_connector_id is called.
    Then: It returns the connector ID.
    """
    from COOCApiModule import get_connector_id

    # Mock context with connector ID
    cloud_info = {"connectorID": "test-connector-id"}
    mock_context = {"CloudIntegrationInfo": cloud_info}
    mocker.patch.object(demisto, "callingContext", {"context": mock_context})
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    # Call function
    result = get_connector_id()

    # Verify result
    assert result == "test-connector-id"
    assert demisto.debug.called


def test_get_connector_id_not_found(mocker):
    """
    Given: A calling context without CloudIntegrationInfo or connectorID.
    When: get_connector_id is called.
    Then: It returns None and logs debug message.
    """
    from COOCApiModule import get_connector_id

    # Mock context without connector ID
    mock_context = {}
    mocker.patch.object(demisto, "callingContext", {"context": mock_context})
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    # Call function
    result = get_connector_id()

    # Verify result
    assert result is None
    assert demisto.debug.called


def test_get_proxydome_token_success(mocker):
    """
    Given: A successful request to the GCP metadata server.
    When: get_proxydome_token is called.
    Then: It returns the identity token.
    """
    from COOCApiModule import get_proxydome_token
    import requests

    # Mock successful response
    mock_response = mocker.MagicMock()
    mock_response.text = "identity-token-12345"
    mocker.patch.object(requests, "get", return_value=mock_response)

    # Call function
    result = get_proxydome_token()

    # Verify result
    assert result == "identity-token-12345"

    # Verify request was made with correct parameters
    requests.get.assert_called_once_with(
        "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity",
        headers={"Metadata-Flavor": "Google"},
        params={"audience": None},
        proxies={"http": "", "https": ""},
    )


def test_get_proxydome_token_request_failure(mocker):
    """
    Given: A failed request to the GCP metadata server.
    When: get_proxydome_token is called.
    Then: It raises a RequestException.
    """
    from COOCApiModule import get_proxydome_token
    import requests

    # Mock failed response
    mocker.patch.object(requests, "get", side_effect=requests.RequestException("Connection failed"))

    # Call function and expect exception
    with pytest.raises(requests.RequestException):
        get_proxydome_token()


def test_provider_account_names():
    """
    Given: The PROVIDER_ACCOUNT_NAMES constant.
    When: Accessing provider account names.
    Then: It contains the expected mappings.
    """
    from COOCApiModule import PROVIDER_ACCOUNT_NAMES

    assert PROVIDER_ACCOUNT_NAMES[CloudTypes.GCP.value] == "Project ID"
    assert PROVIDER_ACCOUNT_NAMES[CloudTypes.AWS.value] == "AWS Account ID"
    assert PROVIDER_ACCOUNT_NAMES[CloudTypes.AZURE.value] == "Subscription ID"
    assert PROVIDER_ACCOUNT_NAMES[CloudTypes.OCI.value] == "Oracle Cloud Account ID"


def test_health_check_error_list(mocker):
    """
    Given: A HealthCheck instance and a list of errors.
    When: The error method is called with a list.
    Then: All errors are added to the health check.
    """
    from COOCApiModule import HealthCheck

    health_check = HealthCheck(connector_id="test-connector-id")

    errors = [
        HealthCheckError(
            account_id="account-1",
            connector_id="test-connector-id",
            message="Error 1",
            error_type=ErrorType.PERMISSION_ERROR,
        ),
        HealthCheckError(
            account_id="account-2",
            connector_id="test-connector-id",
            message="Error 2",
            error_type=ErrorType.CONNECTIVITY_ERROR,
        ),
    ]

    health_check.error(errors)

    assert len(health_check.errors) == 2
    assert health_check.errors[0].account_id == "account-1"
    assert health_check.errors[1].account_id == "account-2"


def test_get_cloud_credentials_no_data_field(mocker):
    """
    Given: An API response without a 'data' field.
    When: get_cloud_credentials is called.
    Then: A DemistoException is raised.
    """

    # Mock context data
    cloud_info = {"connectorID": "test-connector-id", "outpostID": "test-outpost-id"}
    mock_context = {"CloudIntegrationInfo": cloud_info}
    mocker.patch.object(demisto, "callingContext", {"context": mock_context})
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    # Mock platform API response without data field
    api_response = {"status": 200}
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    # Call the function and expect an exception
    with pytest.raises(DemistoException) as excinfo:
        get_cloud_credentials(CloudTypes.AWS.value, account_id="test-account-id")

    assert "Failed to get credentials from CTS" in str(excinfo.value)


def test_get_cloud_credentials_dict_response(mocker):
    """
    Given: An API response with data as a dictionary (not string).
    When: get_cloud_credentials is called.
    Then: It successfully processes the response.
    """

    # Mock context data
    cloud_info = {"connectorID": "test-connector-id", "outpostID": "test-outpost-id"}
    mock_context = {"CloudIntegrationInfo": cloud_info}
    mocker.patch.object(demisto, "callingContext", {"context": mock_context})
    mocker.patch.object(demisto, "info")

    # Mock platform API response with data as dict
    credentials = {"access_token": "test-token", "expiration_time": 1672531200000}
    api_response = {"status": 200, "data": {"data": credentials}}
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    # Call the function
    result = get_cloud_credentials(CloudTypes.AWS.value, account_id="test-account-id")

    # Verify result
    assert result == credentials


def test_return_multiple_permissions_error_valid_entries(mocker):
    """
    Given: A list of valid permission error entries.
    When: return_multiple_permissions_error is called.
    Then: It creates proper error entries and exits with status 0.
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "command", return_value="command")
    mocker.patch.object(demisto, "results")

    error_entries = [
        {"account_id": "account-1", "message": "Permission denied for permission_1", "name": "permission_1"},
        {"account_id": "account-2", "message": "Missing permission_2 permission", "name": "permission_2"},
    ]
    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)

    demisto.debug.assert_called()
    demisto.results.assert_called_once()

    results_call = demisto.results.call_args[0][0]
    assert results_call["Type"] == entryTypes["error"]
    assert results_call["ContentsFormat"] == formats["json"]
    assert len(results_call["Contents"]) == 1
    assert len(results_call["Contents"][0]) == 2

    entries = results_call["Contents"][0]
    assert entries[0]["account_id"] == "account-1"
    assert entries[0]["message"] == "Permission denied for permission_1"
    assert entries[0]["name"] == "permission_1"
    assert entries[0]["classification"] == "WARNING"
    assert entries[0]["error"] == "Permission Error"

    assert entries[1]["account_id"] == "account-2"
    assert entries[1]["message"] == "Missing permission_2 permission"
    assert entries[1]["name"] == "permission_2"

    import sys

    sys.exit.assert_called_once_with(0)


def test_return_multiple_permissions_error_single_entry(mocker):
    """
    Given: A list with a single permission error entry.
    When: return_multiple_permissions_error is called.
    Then: It processes the single entry correctly and exits.
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="command")

    error_entries = [{"account_id": "account-1", "message": "Access denied for permission_1", "name": "permission_1"}]

    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)

    results_call = demisto.results.call_args[0][0]
    entries = results_call["Contents"][0]
    assert len(entries) == 1
    assert entries[0]["account_id"] == "account-1"
    assert entries[0]["message"] == "Access denied for permission_1"
    assert entries[0]["name"] == "permission_1"


def test_return_multiple_permissions_error_empty_list(mocker):
    """
    Given: An empty list of error entries.
    When: return_multiple_permissions_error is called.
    Then: It creates an empty results list and exits.
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="command")

    error_entries = []
    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)

    results_call = demisto.results.call_args[0][0]
    assert results_call["Contents"] == [[]]
    assert results_call["EntryContext"] is None


def test_return_multiple_permissions_error_missing_account_id(mocker):
    """
    Given: Error entries missing account_id field.
    When: return_multiple_permissions_error is called.
    Then: It calls return_error for invalid arguments.
    """
    from COOCApiModule import return_multiple_permissions_error

    error_entries = [{"message": "Permission denied", "name": "permission_1"}]

    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)
        assert demisto.results.call_args[0][0]["Contents"] == "Invalid arguments for permission entry"


def test_return_multiple_permissions_error_missing_message(mocker):
    """
    Given: Error entries missing message field.
    When: return_multiple_permissions_error is called.
    Then: It calls return_error for invalid arguments.
    """
    from COOCApiModule import return_multiple_permissions_error

    error_entries = [{"account_id": "test-account", "name": "permission_1"}]

    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)
        assert demisto.results.call_args[0][0]["Contents"] == "Invalid arguments for permission entry"


def test_return_multiple_permissions_error_missing_name(mocker):
    """
    Given: Error entries missing name field.
    When: return_multiple_permissions_error is called.
    Then: It calls return_error for invalid arguments.
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "command", return_value="command")
    mocker.patch.object(demisto, "results")

    error_entries = [{"account_id": "test-account", "message": "Permission denied"}]

    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)
        assert demisto.results.call_args[0][0]["Contents"] == "Invalid arguments for permission entry"


def test_return_multiple_permissions_error_extra_fields(mocker):
    """
    Given: Error entries with extra fields beyond required ones.
    When: return_multiple_permissions_error is called.
    Then: It processes only the required fields and ignores extras.
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "command", return_value="command")
    mocker.patch.object(demisto, "results")

    error_entries = [
        {
            "account_id": "test-account",
            "message": "Permission denied",
            "name": "permission_1",
            "extra_field": "should_be_ignored",
            "timestamp": "2023-01-01",
        }
    ]
    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)

    results_call = demisto.results.call_args[0][0]
    entries = results_call["Contents"][0]
    assert len(entries) == 1
    assert "extra_field" not in entries[0]
    assert "timestamp" not in entries[0]
    assert entries[0]["account_id"] == "test-account"
    assert entries[0]["message"] == "Permission denied"
    assert entries[0]["name"] == "permission_1"


def test_return_multiple_permissions_error_debug_logging(mocker):
    """
    Given: Valid error entries.
    When: return_multiple_permissions_error is called.
    Then: It logs debug information for the last processed entry.
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="command")

    error_entries = [
        {"account_id": "account-1", "message": "First error", "name": "permission_1"},
        {"account_id": "account-2", "message": "Second error", "name": "permission_2"},
    ]
    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)

    debug_call = demisto.debug.call_args[0][0]
    assert "account-2" in debug_call
    assert "Permission error detected" in debug_call


def test_return_permissions_error_valid_arguments(mocker):
    """
    Given: Valid account_id, message, and name parameters.
    When: return_permissions_error is called.
    Then: It creates proper error entry and exits with status 0.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="command")

    with pytest.raises(SystemExit):
        return_permissions_error("test-account-id", "Permission denied for permission_x", "permission_x")

    demisto.debug.assert_called_once()
    debug_call = demisto.debug.call_args[0][0]
    assert "test-account-id" in debug_call
    assert "Permission error detected" in debug_call

    demisto.results.assert_called_once()
    results_call = demisto.results.call_args[0][0]
    assert results_call["Type"] == entryTypes["error"]
    assert results_call["ContentsFormat"] == formats["json"]
    assert results_call["EntryContext"] is None

    contents = results_call["Contents"]
    assert len(contents) == 1
    error_entry = contents[0]
    assert error_entry["account_id"] == "test-account-id"
    assert error_entry["message"] == "Permission denied for permission_x"
    assert error_entry["name"] == "permission_x"
    assert error_entry["classification"] == "WARNING"
    assert error_entry["error"] == "Permission Error"


def test_return_permissions_error_empty_account_id(mocker):
    """
    Given: Empty account_id parameter.
    When: return_permissions_error is called.
    Then: It calls return_error for invalid arguments.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="command")

    with pytest.raises(SystemExit):
        return_permissions_error("", "Permission denied", "test.permission")


def test_return_permissions_error_empty_message(mocker):
    """
    Given: Empty message parameter.
    When: return_permissions_error is called.
    Then: It calls return_error for invalid arguments.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="command")

    with pytest.raises(SystemExit):
        return_permissions_error("test-account", "", "test.permission")


def test_return_permissions_error_empty_name(mocker):
    """
    Given: Empty name parameter.
    When: return_permissions_error is called.
    Then: It calls return_error for invalid arguments.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="command")

    with pytest.raises(SystemExit):
        return_permissions_error("test-account", "Permission denied", "")


def test_return_permissions_error_none_parameters(mocker):
    """
    Given: None values for parameters.
    When: return_permissions_error is called.
    Then: It calls return_error for invalid arguments.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="command")

    with pytest.raises(SystemExit):
        return_permissions_error(None, None, None)


def test_return_permissions_error_special_characters(mocker):
    """
    Given: Parameters containing special characters.
    When: return_permissions_error is called.
    Then: It handles special characters correctly in the error entry.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="command")

    account_id = "test-account-id"
    message = "Permission denied: 'permission_x' required"
    name = "permission_x"

    with pytest.raises(SystemExit):
        return_permissions_error(account_id, message, name)

    results_call = demisto.results.call_args[0][0]
    error_entry = results_call["Contents"][0]
    assert error_entry["account_id"] == account_id
    assert error_entry["message"] == message
    assert error_entry["name"] == name


def test_return_permissions_error_entry_structure(mocker):
    """
    Given: Valid parameters.
    When: return_permissions_error is called.
    Then: It creates error entry with exact required structure and fields.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="command")

    with pytest.raises(SystemExit):
        return_permissions_error("test-account", "test-message", "test-name")

    results_call = demisto.results.call_args[0][0]
    error_entry = results_call["Contents"][0]

    expected_fields = {"account_id", "message", "name", "classification", "error"}
    actual_fields = set(error_entry.keys())
    assert actual_fields == expected_fields

    assert error_entry["classification"] == "WARNING"
    assert error_entry["error"] == "Permission Error"


def test_return_permissions_error_debug_log_format(mocker):
    """
    Given: Valid parameters.
    When: return_permissions_error is called.
    Then: It logs debug message with correct format including account ID and error details.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="command")

    account_id = "test-account-id"
    with pytest.raises(SystemExit):
        return_permissions_error(account_id, "debug-message", "debug-name")

    debug_call = demisto.debug.call_args[0][0]
    assert "[COOC API]" in debug_call
    assert "Permission error detected" in debug_call
    assert f"account {account_id}" in debug_call
    assert "test-account-id" in debug_call
