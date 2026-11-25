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


def test_get_cloud_credentials_non_string_account_id(mocker):
    """
    Given: A valid cloud type and a non-string account_id (int).
    When: The get_cloud_credentials function is called.
    Then: The account_id is converted to a string and included as a string in the API request.
    """

    cloud_info = {"connectorID": "test-connector-id", "outpostID": "test-outpost-id"}
    mock_context = {"CloudIntegrationInfo": cloud_info}

    mocker.patch.object(demisto, "callingContext", {"context": mock_context})
    mocker.patch.object(demisto, "debug")

    credentials = {"access_token": "test-access-token", "expiration_time": 1672531200000}
    api_response = {
        "status": 200,
        "data": json.dumps({"data": credentials}),
    }
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    non_string_account_id: Any = 123456789012
    result = get_cloud_credentials(CloudTypes.AWS.value, account_id=non_string_account_id)

    assert result == credentials
    call_args = demisto._platformAPICall.call_args[1]
    assert call_args["data"]["request_data"]["account_id"] == "123456789012"
    assert isinstance(call_args["data"]["request_data"]["account_id"], str)


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


@pytest.mark.parametrize(
    "timeout,expected",
    [
        (None, (60, 10)),
        ("", (60, 10)),
        ("30", (30, 10)),
        ("45,15", (45, 15)),
        (120, (120, 10)),
        (0, (0, 10)),
        ("0", (0, 10)),
        (" 30 ", (30, 10)),
        ("45, 15", (45, 15)),
        (" 45 , 15 ", (45, 15)),
    ],
)
def test_get_timeout_valid_inputs(timeout, expected):
    """
    Given: Various valid timeout values (None, empty string, read-only string, read+connect string,
        integer, zero, and strings containing surrounding spaces).
    When: get_timeout is called.
    Then: Returns the correct (read_timeout, connect_timeout) tuple.
    """
    from COOCApiModule import get_timeout

    assert get_timeout(timeout) == expected


def test_get_timeout_malformed_raises():
    """
    Given: A malformed (non-numeric) timeout string.
    When: get_timeout is called.
    Then: Raises DemistoException with a message about read timeout.
    """
    from COOCApiModule import get_timeout
    from CommonServerPython import DemistoException

    with pytest.raises(DemistoException, match="read timeout"):
        get_timeout("not-a-number")


def test_get_timeout_too_many_values_raises():
    """
    Given: A timeout string with more than 2 comma-separated values.
    When: get_timeout is called.
    Then: Raises DemistoException with a message about too many values.
    """
    from COOCApiModule import get_timeout
    from CommonServerPython import DemistoException

    with pytest.raises(DemistoException, match="Too many timeout values"):
        get_timeout("60,10,5")


@pytest.mark.parametrize("bad_timeout", [-5, "-5", "60,-1"])
def test_get_timeout_negative_raises(bad_timeout):
    """
    Given: A timeout value (int or string) containing a negative number.
    When: get_timeout is called.
    Then: Raises DemistoException because timeout values must not be negative.
    """
    from COOCApiModule import get_timeout
    from CommonServerPython import DemistoException

    with pytest.raises(DemistoException, match="Timeout values must not be negative."):
        get_timeout(bad_timeout)


# ----------------------------------------------------------------------
# CloudIntegration
# ----------------------------------------------------------------------


def _make_integration(
    mocker,
    connector_id: str | None = "test-connector-id",
    args: dict | None = None,
    params: dict | None = None,
    account_id_arg: str = "account_id",
):
    """Builds a minimal concrete CloudIntegration subclass for testing the shared logic."""
    from COOCApiModule import CloudIntegration

    class DummyIntegration(CloudIntegration):
        cloud_type = CloudTypes.AWS.value

        def get_client(self):
            return {"creds": self.get_credentials()}

        def health_check(self, credentials, account_id, connector_id):
            return None

        def test_module(self):
            return "ok"

        def handle_error(self, error):
            raise error

    DummyIntegration.account_id_arg = account_id_arg
    mocker.patch("COOCApiModule.get_connector_id", return_value=connector_id)
    return DummyIntegration("test-command", args or {}, params or {})


def test_cloud_integration_init_does_not_fetch_credentials(mocker):
    """
    Given: A CloudIntegration subclass on the platform path.
    When: The integration is constructed.
    Then: Context is stored and CTS is not called (credentials are fetched lazily).
    """
    mock_get_creds = mocker.patch("COOCApiModule.get_cloud_credentials")

    integration = _make_integration(mocker, args={"account_id": "123"})

    assert integration.account_id == "123"
    assert integration.connector_id == "test-connector-id"
    assert integration.credentials == {}
    mock_get_creds.assert_not_called()


def test_cloud_integration_account_id_falls_back_to_params(mocker):
    """
    Given: A subclass with a custom account_id_arg that is only present in params.
    When: The integration is constructed.
    Then: account_id is resolved from params.
    """
    integration = _make_integration(mocker, params={"subscription_id": "sub-1"}, account_id_arg="subscription_id")

    assert integration.account_id == "sub-1"


def test_cloud_integration_get_credentials_marketplace_path(mocker):
    """
    Given: No connector ID (marketplace path).
    When: get_credentials is called.
    Then: Returns {} without calling CTS.
    """
    mock_get_creds = mocker.patch("COOCApiModule.get_cloud_credentials")
    integration = _make_integration(mocker, connector_id=None)

    assert integration.get_credentials() == {}
    mock_get_creds.assert_not_called()


def test_cloud_integration_get_credentials_caches(mocker):
    """
    Given: A platform-path integration.
    When: get_credentials is called twice without scopes.
    Then: CTS is called once and the result is cached.
    """
    mock_get_creds = mocker.patch("COOCApiModule.get_cloud_credentials", return_value={"access_token": "t"})
    integration = _make_integration(mocker, args={"account_id": "123"})

    assert integration.get_credentials() == {"access_token": "t"}
    assert integration.get_credentials() == {"access_token": "t"}
    mock_get_creds.assert_called_once_with(CloudTypes.AWS.value, "123", scopes=None)


def test_cloud_integration_get_credentials_with_scopes_refetches(mocker):
    """
    Given: A platform-path integration with cached credentials.
    When: get_credentials is called with scopes.
    Then: CTS is called again with the requested scopes.
    """
    mock_get_creds = mocker.patch("COOCApiModule.get_cloud_credentials", return_value={"access_token": "t"})
    integration = _make_integration(mocker, args={"account_id": "123"})
    integration.credentials = {"access_token": "old"}

    integration.get_credentials(scopes=["STORAGE"])

    mock_get_creds.assert_called_once_with(CloudTypes.AWS.value, "123", scopes=["STORAGE"])


def test_cloud_integration_execute_command(mocker):
    """
    Given: A platform-path integration and a commands mapping.
    When: execute_command is called.
    Then: The handler is called with (client, args) and its result is returned.
    """
    mocker.patch("COOCApiModule.get_cloud_credentials", return_value={"access_token": "t"})
    integration = _make_integration(mocker, args={"account_id": "123"})
    handler = mocker.Mock(return_value="result")

    result = integration.execute_command({"test-command": handler})

    assert result == "result"
    handler.assert_called_once_with({"creds": {"access_token": "t"}}, {"account_id": "123"})


def test_cloud_integration_execute_command_not_implemented(mocker):
    """
    Given: A command that is neither registered nor in the commands mapping.
    When: execute_command is called.
    Then: NotImplementedError is raised and no client is built.
    """
    integration = _make_integration(mocker, connector_id=None)
    mock_get_client = mocker.patch.object(integration, "get_client")

    with pytest.raises(NotImplementedError, match="Command 'test-command' is not implemented."):
        integration.execute_command({"other-command": mocker.Mock()})
    mock_get_client.assert_not_called()


def test_cloud_integration_register_executes_registered_command(mocker):
    """
    Given: A handler registered with @register for the current command.
    When: execute_command is called with an empty commands mapping.
    Then: The registered handler is called with (client, args) and its result is returned.
    """
    integration = _make_integration(mocker, connector_id=None, args={"a": 1})
    handler = mocker.Mock(return_value="registered")
    type(integration).register("test-command")(handler)

    assert integration.execute_command({}) == "registered"
    handler.assert_called_once_with({"creds": {}}, {"a": 1})


def test_cloud_integration_register_polling_command(mocker):
    """
    Given: A handler registered with polling=True.
    When: execute_command is called.
    Then: The handler is called with (args, client).
    """
    integration = _make_integration(mocker, connector_id=None, args={"a": 1})
    handler = mocker.Mock(return_value="polled")
    type(integration).register("test-command", polling=True)(handler)

    assert integration.execute_command({}) == "polled"
    handler.assert_called_once_with({"a": 1}, {"creds": {}})


def test_cloud_integration_register_takes_precedence_over_mapping(mocker):
    """
    Given: The current command is both registered and in the commands mapping.
    When: execute_command is called.
    Then: The registered handler is used and the mapped one is not called.
    """
    integration = _make_integration(mocker, connector_id=None)
    registered = mocker.Mock(return_value="registered")
    mapped = mocker.Mock(return_value="mapped")
    type(integration).register("test-command")(registered)

    assert integration.execute_command({"test-command": mapped}) == "registered"
    mapped.assert_not_called()


def test_cloud_integration_register_returns_function_unchanged(mocker):
    """
    Given: A function decorated with @register.
    When: The decorator is applied.
    Then: The same function object is returned, so it can still be called directly (e.g. in tests).
    """
    integration = _make_integration(mocker, connector_id=None)

    def handler(client, args):
        return "direct"

    decorated = type(integration).register("test-command")(handler)

    assert decorated is handler
    assert decorated("client", {}) == "direct"


def test_cloud_integration_register_staticmethod_in_service_class(mocker):
    """
    Given: Service class methods registered with @register, stacked in both orders with @staticmethod.
    When: execute_command is called for each command.
    Then: Both handlers are executed, and they remain callable as static methods of the service class.
    """
    integration = _make_integration(mocker, connector_id=None)
    integration_cls = type(integration)

    class Service:
        @staticmethod
        @integration_cls.register("test-command")
        def below_staticmethod(client, args):
            return "below"

        @integration_cls.register("other-command")
        @staticmethod
        def above_staticmethod(client, args):
            return "above"

    assert integration.execute_command({}) == "below"
    integration.command = "other-command"
    assert integration.execute_command({}) == "above"
    assert Service.below_staticmethod("client", {}) == "below"
    assert Service.above_staticmethod("client", {}) == "above"


def test_cloud_integration_register_duplicate_raises(mocker):
    """
    Given: A command name that is already registered on the integration class.
    When: Another handler is registered with the same name.
    Then: ValueError is raised and the original handler is kept.
    """
    integration = _make_integration(mocker, connector_id=None)
    integration_cls = type(integration)
    original = mocker.Mock(return_value="original")
    integration_cls.register("test-command")(original)

    with pytest.raises(ValueError, match="Command 'test-command' is already registered on DummyIntegration."):
        integration_cls.register("test-command")(mocker.Mock())
    assert integration.execute_command({}) == "original"


def test_cloud_integration_register_isolated_per_subclass(mocker):
    """
    Given: Two CloudIntegration subclasses.
    When: A command is registered on one of them.
    Then: It is not visible to the other subclass or to the CloudIntegration base class.
    """
    from COOCApiModule import CloudIntegration

    first = _make_integration(mocker, connector_id=None)
    second = _make_integration(mocker, connector_id=None)
    type(first).register("test-command")(mocker.Mock())

    assert first.get_registered_handler() is not None
    assert second.get_registered_handler() is None
    assert "test-command" not in CloudIntegration._registry


def test_cloud_integration_register_inherited_by_subclass(mocker):
    """
    Given: A command registered on a parent integration class.
    When: The command is executed through a subclass of that integration.
    Then: The parent's registered handler is used.
    """
    parent = _make_integration(mocker, connector_id=None)
    handler = mocker.Mock(return_value="inherited")
    type(parent).register("test-command")(handler)

    class ChildIntegration(type(parent)):  # type: ignore[misc, valid-type]
        pass

    child = ChildIntegration("test-command", {}, {})

    assert child.execute_command({}) == "inherited"


def test_cloud_integration_cloud_type_is_class_attribute(mocker):
    """
    Given: A CloudIntegration subclass that sets cloud_type as a class attribute.
    When: The integration is constructed with (command, args, params) and credentials are fetched.
    Then: The class cloud_type is used for CTS.
    """
    mock_get_creds = mocker.patch("COOCApiModule.get_cloud_credentials", return_value={"access_token": "t"})
    integration = _make_integration(mocker, args={"account_id": "123"})

    integration.get_credentials()

    assert type(integration).cloud_type == CloudTypes.AWS.value
    assert integration.cloud_type == CloudTypes.AWS.value
    mock_get_creds.assert_called_once_with(CloudTypes.AWS.value, "123", scopes=None)


def test_cloud_integration_get_accounts_with_max_results(mocker):
    """
    Given: The onboarding API returns accounts of mixed types.
    When: get_accounts is called with max_results=2.
    Then: Only ACCOUNT-type entries are returned, capped at max_results.
    """
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
    integration = _make_integration(mocker)

    result = integration.get_accounts(max_results=2)

    assert [a["account_id"] for a in result] == ["account-1", "account-2"]


def test_cloud_integration_get_accounts_max_results_zero_returns_empty(mocker):
    """
    Given: The onboarding API returns accounts.
    When: get_accounts is called with max_results=0.
    Then: No accounts are returned and the onboarding API is not called.
    """
    mock_api = mocker.patch.object(demisto, "_platformAPICall")
    integration = _make_integration(mocker)

    assert integration.get_accounts(max_results=0) == []
    mock_api.assert_not_called()


def test_cloud_integration_register_on_base_class_raises():
    """
    Given: The CloudIntegration base class.
    When: register is called on it directly.
    Then: A TypeError is raised and nothing is added to the base registry.
    """
    from COOCApiModule import CloudIntegration

    with pytest.raises(TypeError, match="not on CloudIntegration"):
        CloudIntegration.register("base-command")
    assert "base-command" not in CloudIntegration._registry


def test_cloud_integration_run_handle_proxy_failure_goes_to_handle_error(mocker):
    """
    Given: An integration class with uses_proxy_env set to True, and handle_proxy raises.
    When: run is called.
    Then: The exception is passed to handle_error and the command does not run.
    """
    integration = _make_integration(mocker, connector_id=None)
    mocker.patch.object(type(integration), "uses_proxy_env", True)
    error = ValueError("bad proxy")
    mocker.patch("COOCApiModule.handle_proxy", side_effect=error)
    mocker.patch.object(demisto, "error")
    mock_handle_error = mocker.patch.object(integration, "handle_error")
    handler = mocker.Mock()

    integration.run({"test-command": handler})

    mock_handle_error.assert_called_once_with(error)
    handler.assert_not_called()


def test_cloud_integration_is_polling_command_from_polling_commands(mocker):
    """
    Given: An integration class whose polling_commands contains the current command.
    When: is_polling_command is called.
    Then: It returns True, and False when polling_commands is empty (the default).
    """
    integration = _make_integration(mocker)
    assert integration.is_polling_command() is False

    mocker.patch.object(type(integration), "polling_commands", frozenset({"test-command"}))
    assert integration.is_polling_command() is True


def test_cloud_integration_execute_mapped_command_polling_signature(mocker):
    """
    Given: A mapped handler for a command listed in polling_commands.
    When: execute_mapped_command is called.
    Then: The handler is called with (args, client).
    """
    integration = _make_integration(mocker, connector_id=None, args={"key": "value"})
    mocker.patch.object(type(integration), "polling_commands", frozenset({"test-command"}))
    handler = mocker.Mock(return_value="result")

    assert integration.execute_mapped_command(handler) == "result"
    handler.assert_called_once_with({"key": "value"}, {"creds": {}})


def test_cloud_integration_get_accounts_stops_paging_at_max_results(mocker):
    """
    Given: The onboarding API returns two pages, and the first page has enough accounts.
    When: get_accounts is called with max_results=1.
    Then: Only the first page is requested.
    """
    first_page = {
        "data": json.dumps({"values": [{"account_id": "account-1", "account_type": "ACCOUNT"}], "next_token": "page-2"})
    }
    api_call = mocker.patch.object(demisto, "_platformAPICall", return_value=first_page)
    integration = _make_integration(mocker)

    assert integration.get_accounts(max_results=1) == [{"account_id": "account-1", "account_type": "ACCOUNT"}]
    api_call.assert_called_once()


def test_cloud_integration_get_accounts_all_pages(mocker):
    """
    Given: The onboarding API returns two pages.
    When: get_accounts is called with max_results=None.
    Then: Both pages are requested, the second with the next_token, and all accounts are returned.
    """
    pages = [
        {"data": json.dumps({"values": [{"account_id": "account-1", "account_type": "ACCOUNT"}], "next_token": "page-2"})},
        {"data": json.dumps({"values": [{"account_id": "account-2", "account_type": "ACCOUNT"}], "next_token": ""})},
    ]
    api_call = mocker.patch.object(demisto, "_platformAPICall", side_effect=pages)
    integration = _make_integration(mocker)

    result = integration.get_accounts(max_results=None)

    assert [a["account_id"] for a in result] == ["account-1", "account-2"]
    assert api_call.call_args_list[1].args[2]["next_token"] == "page-2"


def test_cloud_integration_iter_accounts_is_lazy(mocker):
    """
    Given: The onboarding API returns two pages.
    When: Only the first account of iter_accounts is consumed.
    Then: Only the first page is requested.
    """
    first_page = {
        "data": json.dumps({"values": [{"account_id": "account-1", "account_type": "ACCOUNT"}], "next_token": "page-2"})
    }
    api_call = mocker.patch.object(demisto, "_platformAPICall", return_value=first_page)
    integration = _make_integration(mocker)

    assert next(integration.iter_accounts())["account_id"] == "account-1"
    api_call.assert_called_once()


def test_cloud_integration_get_accounts_api_failure_raises(mocker):
    """
    Given: The onboarding API call fails.
    When: get_accounts is called.
    Then: A DemistoException with the failure is raised.
    """
    mocker.patch.object(demisto, "_platformAPICall", side_effect=Exception("api down"))
    integration = _make_integration(mocker)

    with pytest.raises(DemistoException, match="Failed to fetch accounts for connector: api down"):
        integration.get_accounts()


def test_cloud_integration_get_accounts_requires_connector(mocker):
    """
    Given: No connector ID.
    When: get_accounts is called.
    Then: A DemistoException is raised.
    """
    integration = _make_integration(mocker, connector_id=None)

    with pytest.raises(DemistoException, match="requires a connector ID"):
        integration.get_accounts()


def test_cloud_integration_check_account(mocker):
    """
    Given: A health_check implementation.
    When: check_account is called.
    Then: health_check is called with (creds, account_id, connector_id) and its result is returned.
    """
    integration = _make_integration(mocker)
    mock_health_check = mocker.patch.object(integration, "health_check", return_value="health_result")

    result = integration.check_account("account-1", {"access_token": "t"})

    mock_health_check.assert_called_once_with({"access_token": "t"}, "account-1", "test-connector-id")
    assert result == "health_result"


def test_cloud_integration_check_account_exception(mocker):
    """
    Given: A health_check implementation that raises.
    When: check_account is called.
    Then: The exception is converted into an INTERNAL_ERROR HealthCheckError.
    """
    mocker.patch.object(demisto, "error")
    integration = _make_integration(mocker)
    mocker.patch.object(integration, "health_check", side_effect=Exception("Test error"))

    result = integration.check_account("account-1", {})

    assert isinstance(result, HealthCheckError)
    assert result.account_id == "account-1"
    assert result.connector_id == "test-connector-id"
    assert "Test error" in result.message
    assert result.error_type == ErrorType.INTERNAL_ERROR


def test_cloud_integration_run_health_check_no_accounts(mocker):
    """
    Given: A connector with no accounts.
    When: run_health_check is called.
    Then: Returns "ok".
    """
    integration = _make_integration(mocker)
    mocker.patch.object(integration, "get_accounts", return_value=[])

    assert integration.run_health_check() == HealthStatus.OK


def test_cloud_integration_run_health_check_credentials_failure(mocker):
    """
    Given: A connector with accounts but CTS credential retrieval fails.
    When: run_health_check is called.
    Then: Returns CommandResults with a CONNECTIVITY_ERROR.
    """
    mocker.patch.object(demisto, "error")
    mocker.patch("COOCApiModule.get_cloud_credentials", side_effect=Exception("Credential error"))
    integration = _make_integration(mocker)
    mocker.patch.object(integration, "get_accounts", return_value=[{"account_id": "account-1"}])

    result = integration.run_health_check()

    assert isinstance(result, CommandResults)
    raw_response: list = result.raw_response  # type: ignore[assignment]
    assert raw_response[0]["error"] == ErrorType.CONNECTIVITY_ERROR


def test_cloud_integration_run_health_check_healthy(mocker):
    """
    Given: A connector with one healthy account.
    When: run_health_check is called.
    Then: health_check runs with the first account's credentials and "ok" is returned.
    """
    mocker.patch("COOCApiModule.get_cloud_credentials", return_value={"access_token": "t"})
    integration = _make_integration(mocker)
    mocker.patch.object(integration, "get_accounts", return_value=[{"account_id": "account-1"}])
    mock_health_check = mocker.patch.object(integration, "health_check", return_value=None)

    assert integration.run_health_check() == HealthStatus.OK
    mock_health_check.assert_called_once_with({"access_token": "t"}, "account-1", "test-connector-id")


# ----------------------------------------------------------------------
# CloudIntegration command flow: run / execute_mapped_command / handle_error
# ----------------------------------------------------------------------


def test_cloud_integration_run_test_module_platform_path(mocker):
    """
    Given: The test-module command on the Cortex Platform path (connector ID present).
    When: run is called.
    Then: The health check runs and its result is returned; test_module and execute_command are not called.
    """
    integration = _make_integration(mocker, connector_id="test-connector-id")
    integration.command = "test-module"
    mock_health_check = mocker.patch.object(integration, "run_health_check", return_value="ok")
    mock_test_module = mocker.patch.object(integration, "test_module")
    mock_execute = mocker.patch.object(integration, "execute_command")
    mock_return_results = mocker.patch("COOCApiModule.return_results")

    integration.run({})

    mock_health_check.assert_called_once_with()
    mock_test_module.assert_not_called()
    mock_execute.assert_not_called()
    mock_return_results.assert_called_once_with("ok")


def test_cloud_integration_run_test_module_marketplace_path(mocker):
    """
    Given: The test-module command on the marketplace path (no connector ID).
    When: run is called.
    Then: test_module runs and its result is returned; the health check and execute_command are not called.
    """
    integration = _make_integration(mocker, connector_id=None)
    integration.command = "test-module"
    mock_test_module = mocker.patch.object(integration, "test_module", return_value="ok")
    mock_health_check = mocker.patch.object(integration, "run_health_check")
    mock_execute = mocker.patch.object(integration, "execute_command")
    mock_return_results = mocker.patch("COOCApiModule.return_results")

    integration.run({})

    mock_test_module.assert_called_once_with()
    mock_health_check.assert_not_called()
    mock_execute.assert_not_called()
    mock_return_results.assert_called_once_with("ok")


def test_cloud_integration_run_command(mocker):
    """
    Given: A regular command.
    When: run is called.
    Then: execute_command runs with the commands mapping and its result is returned to the War Room.
    """
    integration = _make_integration(mocker, connector_id=None)
    commands_mapping = {"test-command": lambda client, args: "result"}
    mock_return_results = mocker.patch("COOCApiModule.return_results")

    integration.run(commands_mapping)

    mock_return_results.assert_called_once_with("result")


def test_cloud_integration_run_passes_errors_to_handle_error(mocker):
    """
    Given: A command whose handler raises.
    When: run is called.
    Then: The exception is passed to handle_error and nothing is returned.
    """
    integration = _make_integration(mocker, connector_id=None)
    error = ValueError("boom")
    mocker.patch.object(demisto, "error")
    mock_handle_error = mocker.patch.object(integration, "handle_error")
    mock_return_results = mocker.patch("COOCApiModule.return_results")

    integration.run({"test-command": mocker.Mock(side_effect=error)})

    mock_handle_error.assert_called_once_with(error)
    mock_return_results.assert_not_called()


def test_cloud_integration_run_logs_traceback_once_on_error(mocker):
    """
    Given: A command whose handler raises.
    When: run is called.
    Then: run logs the traceback once with demisto.error before calling handle_error.
    """
    integration = _make_integration(mocker, connector_id=None)
    mock_error = mocker.patch.object(demisto, "error")
    mocker.patch.object(integration, "handle_error")

    integration.run({"test-command": mocker.Mock(side_effect=ValueError("boom"))})

    mock_error.assert_called_once()
    assert "ValueError: boom" in mock_error.call_args[0][0]


def test_cloud_integration_run_registered_command_success(mocker):
    """
    Given: A handler registered with @register for the current command and an empty commands mapping.
    When: run is called.
    Then: The registered handler gets (client, args) and its result is passed to return_results.
    """
    integration = _make_integration(mocker, connector_id=None, args={"key": "value"})
    handler = mocker.Mock(return_value="registered-result")
    type(integration).register("test-command")(handler)
    mock_return_results = mocker.patch("COOCApiModule.return_results")
    mock_handle_error = mocker.patch.object(integration, "handle_error")

    integration.run({})

    handler.assert_called_once_with({"creds": {}}, {"key": "value"})
    mock_return_results.assert_called_once_with("registered-result")
    mock_handle_error.assert_not_called()


def test_cloud_integration_run_registered_polling_command_success(mocker):
    """
    Given: A handler registered with polling=True for the current command.
    When: run is called.
    Then: The registered handler gets (args, client) and its result is passed to return_results.
    """
    integration = _make_integration(mocker, connector_id=None, args={"key": "value"})
    handler = mocker.Mock(return_value="polling-result")
    type(integration).register("test-command", polling=True)(handler)
    mock_return_results = mocker.patch("COOCApiModule.return_results")

    integration.run({})

    handler.assert_called_once_with({"key": "value"}, {"creds": {}})
    mock_return_results.assert_called_once_with("polling-result")


def test_cloud_integration_run_registered_command_error(mocker):
    """
    Given: A registered handler that raises.
    When: run is called.
    Then: The exception is passed to handle_error and return_results is not called.
    """
    integration = _make_integration(mocker, connector_id=None)
    error = RuntimeError("registered failure")
    type(integration).register("test-command")(mocker.Mock(side_effect=error))
    mocker.patch.object(demisto, "error")
    mock_return_results = mocker.patch("COOCApiModule.return_results")
    mock_handle_error = mocker.patch.object(integration, "handle_error")

    integration.run({})

    mock_handle_error.assert_called_once_with(error)
    mock_return_results.assert_not_called()


def test_cloud_integration_run_registered_command_preferred_over_mapping(mocker):
    """
    Given: A command that is both registered and present in the commands mapping.
    When: run is called.
    Then: Only the registered handler runs.
    """
    integration = _make_integration(mocker, connector_id=None)
    registered = mocker.Mock(return_value="registered")
    mapped = mocker.Mock(return_value="mapped")
    type(integration).register("test-command")(registered)
    mock_return_results = mocker.patch("COOCApiModule.return_results")

    integration.run({"test-command": mapped})

    registered.assert_called_once()
    mapped.assert_not_called()
    mock_return_results.assert_called_once_with("registered")


def test_cloud_integration_run_calls_handle_proxy_when_enabled(mocker):
    """
    Given: An integration class with uses_proxy_env set to True.
    When: run is called.
    Then: handle_proxy is called.
    """
    integration = _make_integration(mocker, connector_id=None)
    mocker.patch.object(type(integration), "uses_proxy_env", True)
    mock_handle_proxy = mocker.patch("COOCApiModule.handle_proxy")
    mocker.patch("COOCApiModule.return_results")

    integration.run({"test-command": lambda client, args: "result"})

    mock_handle_proxy.assert_called_once_with()


def test_cloud_integration_run_skips_handle_proxy_by_default(mocker):
    """
    Given: An integration class with the default uses_proxy_env (False).
    When: run is called.
    Then: handle_proxy is not called.
    """
    integration = _make_integration(mocker, connector_id=None)
    mock_handle_proxy = mocker.patch("COOCApiModule.handle_proxy")
    mocker.patch("COOCApiModule.return_results")

    integration.run({"test-command": lambda client, args: "result"})

    mock_handle_proxy.assert_not_called()


def test_cloud_integration_execute_command_uses_execute_mapped_command(mocker):
    """
    Given: A subclass that overrides execute_mapped_command with a different handler signature.
    When: execute_command is called for a mapped (not registered) command.
    Then: The override calls the handler, so each CSP controls how its existing handlers are called.
    """
    integration = _make_integration(mocker, args={"key": "value"})
    handler = mocker.Mock(return_value="result")
    mocker.patch.object(integration, "execute_mapped_command", side_effect=lambda h: h(integration.args))

    assert integration.execute_command({"test-command": handler}) == "result"
    handler.assert_called_once_with({"key": "value"})


def test_cloud_integration_execute_mapped_command_default_signature(mocker):
    """
    Given: A mapped handler.
    When: execute_mapped_command is called.
    Then: The handler is called with (client, args) by default.
    """
    integration = _make_integration(mocker, connector_id=None, args={"key": "value"})
    handler = mocker.Mock(return_value="result")

    assert integration.execute_mapped_command(handler) == "result"
    handler.assert_called_once_with({"creds": {}}, {"key": "value"})


def test_cloud_integration_handle_error_default(mocker):
    """
    Given: A subclass that does not override handle_error.
    When: handle_error is called.
    Then: return_error is called with the command name and the error, and no traceback is logged
          (run logs it before calling handle_error).
    """
    from COOCApiModule import CloudIntegration

    class MinimalIntegration(CloudIntegration):
        cloud_type = CloudTypes.AWS.value

        def get_client(self):
            return None

        def health_check(self, credentials, account_id, connector_id):
            return None

        def test_module(self):
            return "ok"

    mocker.patch("COOCApiModule.get_connector_id", return_value=None)
    mock_error = mocker.patch.object(demisto, "error")
    mock_return_error = mocker.patch("COOCApiModule.return_error")
    integration = MinimalIntegration("my-command", {}, {})

    integration.handle_error(ValueError("boom"))

    mock_error.assert_not_called()
    mock_return_error.assert_called_once_with("Failed to execute my-command command.\nError:\nboom")
