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


def test_create_permissions_error_entry_success():
    """
    Given: Valid account_id, message, and name parameters.
    When: create_permissions_error_entry is called.
    Then: It returns a properly formatted error entry dictionary.
    """
    from COOCApiModule import create_permissions_error_entry

    account_id = "account_id"
    message = "Permission denied for permission"
    name = "permission"

    result = create_permissions_error_entry(account_id, message, name)

    assert result["account_id"] == account_id
    assert result["message"] == message
    assert result["name"] == name
    assert result["classification"] == "WARNING"
    assert result["error"] == "Permission Error"


def test_create_permissions_error_entry_with_debug_logging(mocker):
    """
    Given: Valid parameters for creating a permission error entry.
    When: create_permissions_error_entry is called.
    Then: It logs the appropriate debug message.
    """
    from COOCApiModule import create_permissions_error_entry

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")

    account_id = "account_id"
    message = "Access denied for permission"
    name = "permission"

    create_permissions_error_entry(account_id, message, name)

    demisto.debug.assert_called_once()
    debug_call_args = demisto.debug.call_args[0][0]
    assert f"Permission error detected for account {account_id}" in debug_call_args
    assert account_id in debug_call_args


def test_return_multiple_permissions_error_single_entry(mocker):
    """
    Given: A single valid error entry in the error_entries list.
    When: return_multiple_permissions_error is called.
    Then: It creates a single error entry, logs it, and calls demisto.results with sys.exit(0).
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")

    error_entries = [{"account_id": "account_id", "message": "Permission denied for permission", "name": "permission"}]
    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)

    debug_call = demisto.debug.call_args[0][0]
    assert "Permission error detected for account account_id" in debug_call

    demisto.results.assert_called_once()
    results_call = demisto.results.call_args[0][0]
    assert results_call["Type"] == entryTypes["error"]
    assert results_call["ContentsFormat"] == formats["json"]
    assert results_call["Contents"][0]["account_id"] == "account_id"


def test_return_multiple_permissions_error_multiple_entries(mocker):
    """
    Given: Multiple valid error entries in the error_entries list.
    When: return_multiple_permissions_error is called.
    Then: It creates multiple error entries, logs each one, and calls demisto.results with all entries.
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")

    error_entries = [
        {"account_id": "account-1", "message": "Permission denied for permission", "name": "permission"},
        {"account_id": "account-2", "message": "Access denied for permission", "name": "permission"},
        {"account_id": "account-3", "message": "Insufficient permissions for permission", "name": "permission"},
    ]
    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)

    assert demisto.debug.call_count == 6

    debug_calls = [call[0][0] for call in demisto.debug.call_args_list]
    assert "Permission error detected for account account-1" in debug_calls[0]
    assert "Permission error detected for account account-2" in debug_calls[2]
    assert "Permission error detected for account account-3" in debug_calls[4]

    demisto.results.assert_called_once()
    results_call = demisto.results.call_args[0][0]
    assert len(results_call["Contents"]) == 3
    assert results_call["Contents"][0]["account_id"] == "account-1"
    assert results_call["Contents"][1]["account_id"] == "account-2"
    assert results_call["Contents"][2]["account_id"] == "account-3"


def test_return_multiple_permissions_error_empty_list(mocker):
    """
    Given: An empty error_entries list.
    When: return_multiple_permissions_error is called.
    Then: It creates an empty results list and still calls sys.exit(0).
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")

    error_entries = []
    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)

    demisto.debug.assert_not_called()

    demisto.results.assert_called_once()
    results_call = demisto.results.call_args[0][0]
    assert len(results_call["Contents"]) == 0


def test_return_multiple_permissions_error_entry_context_is_none(mocker):
    """
    Given: Valid error entries.
    When: return_multiple_permissions_error is called.
    Then: The EntryContext field in demisto.results is set to None.
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")

    error_entries = [{"account_id": "account_id", "message": "test error", "name": "test.permission"}]
    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)

    results_call = demisto.results.call_args[0][0]
    assert results_call["EntryContext"] is None


def test_return_multiple_permissions_error_correct_format_and_type(mocker):
    """
    Given: Valid error entries.
    When: return_multiple_permissions_error is called.
    Then: The demisto.results call uses the correct Type and ContentsFormat.
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")

    error_entries = [{"account_id": "account_id", "message": "format test error", "name": "permission"}]
    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)

    results_call = demisto.results.call_args[0][0]
    assert results_call["Type"] == entryTypes["error"]
    assert results_call["ContentsFormat"] == formats["json"]
    assert isinstance(results_call["Contents"], list)
    assert isinstance(results_call["Contents"][0], dict)


def test_return_multiple_permissions_error_debug_logging_format(mocker):
    """
    Given: Valid error entries with specific account IDs.
    When: return_multiple_permissions_error is called.
    Then: Debug logging includes the correct format with account ID and error details.
    """
    from COOCApiModule import return_multiple_permissions_error

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")

    error_entries = [{"account_id": "account_id", "message": "Debug test permission error", "name": "debug.test.permission"}]
    with pytest.raises(SystemExit):
        return_multiple_permissions_error(error_entries)

    debug_call = demisto.debug.call_args[0][0]
    assert "[COOC API]" in debug_call
    assert "Permission error detected for account account_id" in debug_call
    assert debug_call.endswith(
        ": {'account_id': 'account_id', 'message': 'Debug test permission error', "
        "'name': 'debug.test.permission', 'classification': 'WARNING', 'error': 'Permission Error'}"
    )


def test_create_permissions_error_entry_none_account_id_string_message_name(mocker):
    """
    Given: A None account_id with valid string message and name.
    When: create_permissions_error_entry is called.
    Then: It sets account_id to "N/A" and logs an info message about invalid entry.
    """
    from COOCApiModule import create_permissions_error_entry

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    result = create_permissions_error_entry(None, "Valid message", "valid.permission")

    assert result["account_id"] == "N/A"
    assert result["message"] == "Valid message"
    assert result["name"] == "valid.permission"
    assert result["classification"] == "WARNING"
    assert result["error"] == "Permission Error"

    demisto.info.assert_called_once()
    info_call = demisto.info.call_args[0][0]
    assert "[COOC API] Invalid entry was given to the permissions entry" in info_call
    assert "account_id" in info_call


def test_create_permissions_error_entry_whitespace_only_account_id(mocker):
    """
    Given: An account_id containing only whitespace characters.
    When: create_permissions_error_entry is called.
    Then: It sets account_id to "N/A" and logs an info message.
    """
    from COOCApiModule import create_permissions_error_entry

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    result = create_permissions_error_entry("   ", "Valid message", "valid.permission")

    assert result["account_id"] == "N/A"
    assert result["message"] == "Valid message"
    assert result["name"] == "valid.permission"

    demisto.info.assert_called_once()
    info_call = demisto.info.call_args[0][0]
    assert "account_id" in info_call


def test_create_permissions_error_entry_whitespace_only_message(mocker):
    """
    Given: A message containing only whitespace characters.
    When: create_permissions_error_entry is called.
    Then: It sets message to "N/A" and logs an info message.
    """
    from COOCApiModule import create_permissions_error_entry

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    result = create_permissions_error_entry("valid-account", "\t\n  ", "valid.permission")

    assert result["account_id"] == "valid-account"
    assert result["message"] == "N/A"
    assert result["name"] == "valid.permission"

    demisto.info.assert_called_once()
    info_call = demisto.info.call_args[0][0]
    assert "message" in info_call


def test_create_permissions_error_entry_whitespace_only_name(mocker):
    """
    Given: A name containing only whitespace characters.
    When: create_permissions_error_entry is called.
    Then: It sets name to "N/A" and logs an info message.
    """
    from COOCApiModule import create_permissions_error_entry

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    result = create_permissions_error_entry("valid-account", "Valid message", "  \r\n")

    assert result["account_id"] == "valid-account"
    assert result["message"] == "Valid message"
    assert result["name"] == "N/A"

    demisto.info.assert_called_once()
    info_call = demisto.info.call_args[0][0]
    assert "name" in info_call


def test_create_permissions_error_entry_multiple_invalid_parameters(mocker):
    """
    Given: Multiple parameters that are None or empty.
    When: create_permissions_error_entry is called.
    Then: It sets all invalid parameters to "N/A" and logs multiple info messages.
    """
    from COOCApiModule import create_permissions_error_entry

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    result = create_permissions_error_entry(None, "", "  ")

    assert result["account_id"] == "N/A"
    assert result["message"] == "N/A"
    assert result["name"] == "N/A"
    assert result["classification"] == "WARNING"
    assert result["error"] == "Permission Error"

    assert demisto.info.call_count == 3


def test_create_permissions_error_entry_all_valid_no_info_log(mocker):
    """
    Given: All valid non-empty parameters.
    When: create_permissions_error_entry is called.
    Then: It does not call demisto.info and only calls demisto.debug.
    """
    from COOCApiModule import create_permissions_error_entry

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    result = create_permissions_error_entry("valid-account", "Valid error message", "permission.name")

    assert result["account_id"] == "valid-account"
    assert result["message"] == "Valid error message"
    assert result["name"] == "permission.name"

    demisto.info.assert_not_called()
    demisto.debug.assert_called_once()


def test_create_permissions_error_entry_info_log_content_format(mocker):
    """
    Given: An invalid parameter value.
    When: create_permissions_error_entry is called.
    Then: The info log contains the exact format with variable name and value.
    """
    from COOCApiModule import create_permissions_error_entry

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    create_permissions_error_entry("", "Valid message", "valid.permission")

    info_call = demisto.info.call_args[0][0]
    assert info_call == "[COOC API] Invalid entry was given to the permissions entry var_name='account_id':var_value=''."


def test_create_permissions_error_entry_debug_log_with_na_values(mocker):
    """
    Given: Parameters that get converted to "N/A".
    When: create_permissions_error_entry is called.
    Then: The debug log shows the final entry with "N/A" values.
    """
    from COOCApiModule import create_permissions_error_entry

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    create_permissions_error_entry(None, "Valid message", "")

    debug_call = demisto.debug.call_args[0][0]
    assert "[COOC API] Permission error detected for account N/A:" in debug_call
    assert "'account_id': 'N/A'" in debug_call
    assert "'name': 'N/A'" in debug_call


def test_create_permissions_error_entry_integer_zero_as_string(mocker):
    """
    Given: A string "0" as account_id.
    When: create_permissions_error_entry is called.
    Then: It treats "0" as valid and does not convert to "N/A".
    """
    from COOCApiModule import create_permissions_error_entry

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    result = create_permissions_error_entry("0", "Valid message", "valid.permission")

    assert result["account_id"] == "0"
    assert result["message"] == "Valid message"
    assert result["name"] == "valid.permission"

    demisto.info.assert_not_called()


def test_is_gov_account_gov_partition_true(mocker):
    """
    Given: A connector_id, account_id, and accounts with GOV partition.
    When: is_gov_account is called.
    Then: It returns True for the account with GOV partition.
    """
    from COOCApiModule import is_gov_account

    # Mock get_accounts_by_connector_id
    accounts = [
        {"account_id": "account-1", "cloud_partition": "GOV"},
        {"account_id": "account-2", "cloud_partition": "COMMERCIAL"},
    ]
    mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=accounts)
    mocker.patch.object(demisto, "debug")

    # Call function
    result = is_gov_account("test-connector-id", "account-1")

    # Verify result
    assert result is True


def test_is_gov_account_standard_partition_false(mocker):
    """
    Given: A connector_id, account_id, and accounts with COMMERCIAL partition.
    When: is_gov_account is called.
    Then: It returns False for the account with COMMERCIAL partition.
    """
    from COOCApiModule import is_gov_account

    # Mock get_accounts_by_connector_id
    accounts = [
        {"account_id": "account-1", "cloud_partition": "COMMERCIAL"},
        {"account_id": "account-2", "cloud_partition": "GOV"},
    ]
    mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=accounts)
    mocker.patch.object(demisto, "debug")

    # Call function
    result = is_gov_account("test-connector-id", "account-1")

    # Verify result
    assert result is False


def test_is_gov_account_not_found_false(mocker):
    """
    Given: A connector_id, account_id, and accounts list without the requested account.
    When: is_gov_account is called.
    Then: It returns False for non-existent account.
    """
    from COOCApiModule import is_gov_account

    # Mock get_accounts_by_connector_id
    accounts = [{"account_id": "account-1", "cloud_partition": "STANDARD"}, {"account_id": "account-2", "cloud_partition": "GOV"}]
    mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=accounts)
    mocker.patch.object(demisto, "debug")

    # Call function
    result = is_gov_account("test-connector-id", "account-3")

    # Verify result
    assert result is False


def test_is_gov_account_empty_accounts_list(mocker):
    """
    Given: A connector_id, account_id, and empty accounts list.
    When: is_gov_account is called.
    Then: It returns False for empty accounts list.
    """
    from COOCApiModule import is_gov_account

    # Mock get_accounts_by_connector_id
    accounts = []
    mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=accounts)
    mocker.patch.object(demisto, "debug")

    # Call function
    result = is_gov_account("test-connector-id", "account-1")

    # Verify result
    assert result is False


def test_is_gov_account_missing_cloud_partition(mocker):
    """
    Given: A connector_id, account_id, and account without cloud_partition field.
    When: is_gov_account is called.
    Then: It returns False for account missing cloud_partition.
    """
    from COOCApiModule import is_gov_account

    # Mock get_accounts_by_connector_id
    accounts = [{"account_id": "account-1"}, {"account_id": "account-2", "cloud_partition": "GOV"}]
    mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=accounts)
    mocker.patch.object(demisto, "debug")

    # Call function
    result = is_gov_account("test-connector-id", "account-1")

    # Verify result
    assert result is False


def test_is_gov_account_null_cloud_partition(mocker):
    """
    Given: A connector_id, account_id, and account with None cloud_partition.
    When: is_gov_account is called.
    Then: It returns False for account with None cloud_partition.
    """
    from COOCApiModule import is_gov_account

    # Mock get_accounts_by_connector_id
    accounts = [{"account_id": "account-1", "cloud_partition": None}, {"account_id": "account-2", "cloud_partition": "GOV"}]
    mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=accounts)
    mocker.patch.object(demisto, "debug")

    # Call function
    result = is_gov_account("test-connector-id", "account-1")

    # Verify result
    assert result is False


def test_is_gov_account_case_sensitive_partition(mocker):
    """
    Given: A connector_id, account_id, and account with lowercase 'gov' partition.
    When: is_gov_account is called.
    Then: It returns True for non case-sensitive partition check.
    """
    from COOCApiModule import is_gov_account

    # Mock get_accounts_by_connector_id
    accounts = [{"account_id": "account-1", "cloud_partition": "gov"}, {"account_id": "account-2", "cloud_partition": "GOV"}]
    mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=accounts)
    mocker.patch.object(demisto, "debug")

    # Call function
    result = is_gov_account("test-connector-id", "account-1")

    # Verify result
    assert result is True


def test_is_gov_account_get_accounts_call_parameters(mocker):
    """
    Given: A connector_id and account_id.
    When: is_gov_account is called.
    Then: It calls get_accounts_by_connector_id with correct parameters.
    """
    from COOCApiModule import is_gov_account

    # Mock get_accounts_by_connector_id
    accounts = [{"account_id": "account-1", "cloud_partition": "GOV"}]
    mock_get_accounts = mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=accounts)
    mocker.patch.object(demisto, "debug")

    # Call function
    is_gov_account("test-connector-id", "account-1")

    # Verify get_accounts_by_connector_id was called with correct parameters
    mock_get_accounts.assert_called_once_with("test-connector-id", None)
