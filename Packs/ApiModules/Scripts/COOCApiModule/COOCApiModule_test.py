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


def test_return_permissions_error_with_valid_dict(mocker):
    """
    Given: A valid error_entry dictionary with account_id, message, and name.
    When: return_permissions_error is called.
    Then: It logs the error, returns formatted results, and exits.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch("sys.exit")

    error_entry = {"account_id": "test-account-123", "message": "Permission denied: permission", "name": "permission"}

    return_permissions_error(error_entry)

    demisto.debug.assert_called_once_with(
        "[COOC API] Permission error detected for account test-account-123: " + str(error_entry)
    )

    expected_results = {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["json"],
        "Contents": [error_entry.update({"classification": "WARNING", "error": "Permission Error"})],
        "EntryContext": None,
    }
    demisto.results.assert_called_once_with(expected_results)

    import sys

    sys.exit.assert_called_once_with(0)


def test_return_permissions_error_with_missing_account_id(mocker):
    """
    Given: An error_entry dictionary without account_id field.
    When: return_permissions_error is called.
    Then: It handles the missing field gracefully and still processes the error.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch("sys.exit")

    error_entry = {"message": "Permission denied: permission", "name": "permission"}

    return_permissions_error(error_entry)

    demisto.debug.assert_called_once_with("[COOC API] Permission error detected for account None: " + str(error_entry))

    expected_results = {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["json"],
        "Contents": [error_entry.update({"classification": "WARNING", "error": "Permission Error"})],
        "EntryContext": None,
    }
    demisto.results.assert_called_once_with(expected_results)

    import sys

    sys.exit.assert_called_once_with(0)


def test_return_permissions_error_with_empty_dict(mocker):
    """
    Given: An empty error_entry dictionary.
    When: return_permissions_error is called.
    Then: It processes the empty dictionary and logs with None account_id.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch("sys.exit")

    error_entry = {}

    return_permissions_error(error_entry)

    demisto.debug.assert_called_once_with("[COOC API] Permission error detected for account None: {}")

    expected_results = {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["json"],
        "Contents": [{}.update({"classification": "WARNING", "error": "Permission Error"})],
        "EntryContext": None,
    }
    demisto.results.assert_called_once_with(expected_results)

    import sys

    sys.exit.assert_called_once_with(0)


def test_return_permissions_error_with_invalid_type_string(mocker):
    """
    Given: A string instead of a dictionary for error_entry.
    When: return_permissions_error is called.
    Then: It logs the invalid type error and creates a default error entry.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch("sys.exit")

    error_entry = "invalid string input"

    return_permissions_error(error_entry)

    demisto.error.assert_called_once_with("[COOC API] Invalid error_entry type: <class 'str'>")

    default_error = {"message": "Invalid error data provided", "error_type": "Internal Error"}
    demisto.debug.assert_called_once_with("[COOC API] Permission error detected for account None: " + str(default_error))

    expected_results = {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["json"],
        "Contents": [default_error.update({"classification": "WARNING", "error": "Permission Error"})],
        "EntryContext": None,
    }
    demisto.results.assert_called_once_with(expected_results)

    import sys

    sys.exit.assert_called_once_with(0)


def test_return_permissions_error_with_invalid_type_list(mocker):
    """
    Given: A list instead of a dictionary for error_entry.
    When: return_permissions_error is called.
    Then: It logs the invalid type error and creates a default error entry.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch("sys.exit")

    error_entry = ["item1", "item2"]

    return_permissions_error(error_entry)

    demisto.error.assert_called_once_with("[COOC API] Invalid error_entry type: <class 'list'>")

    default_error = {"message": "Invalid error data provided", "error_type": "Internal Error"}
    demisto.debug.assert_called_once_with("[COOC API] Permission error detected for account None: " + str(default_error))

    expected_results = {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["json"],
        "Contents": [default_error.update({"classification": "WARNING", "error": "Permission Error"})],
        "EntryContext": None,
    }
    demisto.results.assert_called_once_with(expected_results)

    import sys

    sys.exit.assert_called_once_with(0)


def test_return_permissions_error_with_none_input(mocker):
    """
    Given: None as input for error_entry.
    When: return_permissions_error is called.
    Then: It logs the invalid type error and creates a default error entry.
    """
    from COOCApiModule import return_permissions_error

    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    mocker.patch("sys.exit")

    error_entry = None

    return_permissions_error(error_entry)

    demisto.error.assert_called_once_with("[COOC API] Invalid error_entry type: <class 'NoneType'>")

    default_error = {"message": "Invalid error data provided", "error_type": "Internal Error"}
    demisto.debug.assert_called_once_with("[COOC API] Permission error detected for account None: " + str(default_error))

    expected_results = {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["json"],
        "Contents": [default_error.update({"classification": "WARNING", "error": "Permission Error"})],
        "EntryContext": None,
    }
    demisto.results.assert_called_once_with(expected_results)

    import sys

    sys.exit.assert_called_once_with(0)
