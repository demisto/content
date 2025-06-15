import json
import pytest
from CommonServerPython import *
from COOCApiModule import CloudTypes, get_cloud_credentials
import demistomock as demisto


def test_get_cloud_credentials_success(mocker):
    """
    Given: A valid cloud type and calling context with required cloud information.
    When: The get_cloud_credentials function is called.
    Then: Function successfully returns the credentials dictionary from the platform API response.
    """

    # Mock context data
    cloud_info = {"connectorID": "test-connector-id", "accountID": "test-account-id", "outpostID": "test-outpost-id"}
    mock_context = {"CloudIntegrationProviderInfo": cloud_info}

    # Mock the demisto functions directly
    mocker.patch.object(demisto, "callingContext", return_value={"context": mock_context})
    mocker.patch.object(demisto, "info")

    # Mock platform API response with credentials
    credentials = {"access_token": "test-access-token", "expiration_time": "2023-01-01T00:00:00Z"}
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
    mock_context = {"CloudIntegrationProviderInfo": cloud_info}
    mocker.patch.object(demisto, "callingContext", return_value={"context": mock_context})
    mocker.patch.object(demisto, "info")

    # Mock platform API response
    credentials = {"access_token": "test-access-token", "expiration_time": "2023-01-01T00:00:00Z"}
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


def test_get_cloud_credentials_api_error(mocker):
    """
    Given: A valid cloud type but the API returns an error.
    When: The get_cloud_credentials function is called.
    Then: A DemistoException is raised with the error details.
    """

    # Mock context data
    cloud_info = {"connectorID": "test-connector-id", "accountID": "test-account-id", "outpostID": "test-outpost-id"}
    mock_context = {"CloudIntegrationProviderInfo": cloud_info}
    mocker.patch.object(demisto, "callingContext", return_value={"context": mock_context})
    mocker.patch.object(demisto, "info")

    # Mock platform API error response
    api_response = {"status": 400, "data": "Bad request"}
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    # Call the function and expect an exception
    with pytest.raises(DemistoException) as excinfo:
        get_cloud_credentials(CloudTypes.AZURE.value, account_id="test-account-id")

    # Verify exception message
    assert "Failed to get credentials from CTS for AZURE" in str(excinfo.value)
    assert "Status code: 400" in str(excinfo.value)
    assert "Error: Bad request" in str(excinfo.value)


def test_get_cloud_credentials_parse_error(mocker):
    """
    Given: A valid cloud type but the API returns a malformed response.
    When: The get_cloud_credentials function is called.
    Then: A DemistoException is raised due to parsing failure.
    """

    # Mock context data
    cloud_info = {"connectorID": "test-connector-id", "accountID": "test-account-id", "outpostID": "test-outpost-id"}
    mock_context = {"CloudIntegrationProviderInfo": cloud_info}
    mocker.patch.object(demisto, "callingContext", return_value={"context": mock_context})
    mocker.patch.object(demisto, "info")

    # Mock platform API with invalid JSON
    api_response = {"status": 200, "data": "Not a valid JSON"}
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    # Call the function and expect an exception
    with pytest.raises(DemistoException) as excinfo:
        get_cloud_credentials(CloudTypes.OCI.value, account_id="test-account-id")

    # Verify exception message
    assert "Failed to parse credentials from CTS response for OCI" in str(excinfo.value)


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
            {"values": [{"account_id": "account-1"}, {"account_id": "account-2"}, {"account_id": "account-3"}], "next_token": ""}
        ),
    }
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

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
    from COOCApiModule import HealthCheckError, ErrorType, HealthStatus

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
    from COOCApiModule import HealthCheck, HealthStatus

    # Create HealthCheck with no errors
    health_check = HealthCheck(connector_id="test-connector-id")

    # Call summarize
    result = health_check.summarize()

    # Verify result
    assert result == HealthStatus.OK


def test_check_account_permissions(mocker):
    """
    Given: An account, connector_id, and permission check function.
    When: _check_account_permissions is called.
    Then: It calls the permission check function with the correct parameters and returns its result.
    """
    import demistomock as demisto
    from COOCApiModule import _check_account_permissions

    # Mock permission check function
    mock_permission_check = mocker.Mock(return_value="permission_check_result")

    # Test with valid account
    account = {"account_id": "test-account-id"}
    result = _check_account_permissions(account, "test-connector-id", mock_permission_check)

    # Verify permission check was called with correct parameters
    mock_permission_check.assert_called_once_with("test-account-id", "test-connector-id")
    assert result == "permission_check_result"


def test_check_account_permissions_no_account_id(mocker):
    """
    Given: An account without account_id, connector_id, and permission check function.
    When: _check_account_permissions is called.
    Then: It logs a debug message and returns None.
    """
    import demistomock as demisto
    from COOCApiModule import _check_account_permissions

    # Mock permission check function and debug function
    mock_permission_check = mocker.Mock()
    mocker.patch.object(demisto, "debug")

    # Test with account missing account_id
    account = {"name": "test-account"}
    result = _check_account_permissions(account, "test-connector-id", mock_permission_check)

    # Verify permission check was not called and debug was logged
    assert not mock_permission_check.called
    assert demisto.debug.called
    assert result is None


def test_check_account_permissions_exception(mocker):
    """
    Given: An account, connector_id, and permission check function that raises an exception.
    When: _check_account_permissions is called.
    Then: It handles the exception and returns a HealthCheckError.
    """
    import demistomock as demisto
    from COOCApiModule import _check_account_permissions, HealthCheckError, ErrorType

    # Mock permission check function to raise exception
    mock_permission_check = mocker.Mock(side_effect=Exception("Test error"))
    mocker.patch.object(demisto, "error")

    # Test with exception in permission check
    account = {"account_id": "test-account-id"}
    result = _check_account_permissions(account, "test-connector-id", mock_permission_check)

    # Verify error was logged and HealthCheckError returned
    assert demisto.error.called
    assert isinstance(result, HealthCheckError)
    assert result.account_id == "test-account-id"
    assert result.connector_id == "test-connector-id"
    assert "Test error" in result.message
    assert result.error_type == ErrorType.INTERNAL_ERROR


def test_run_permissions_check_for_accounts(mocker):
    """
    Given: A connector_id and permission check function.
    When: run_permissions_check_for_accounts is called.
    Then: It retrieves accounts and runs permission checks concurrently.
    """
    from COOCApiModule import run_permissions_check_for_accounts, HealthCheck, HealthCheckError, ErrorType, HealthStatus

    # Mock get_accounts_by_connector_id
    accounts = [{"account_id": "account-1"}, {"account_id": "account-2"}]
    mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=accounts)

    # Mock HealthCheck
    mock_health_check = mocker.MagicMock()
    mock_health_check.summarize.return_value = "health_check_result"
    mocker.patch("COOCApiModule.HealthCheck", return_value=mock_health_check)

    # Create a permission check function that adds errors to the health check
    def mock_permission_check(account_id, connector_id):
        if account_id == "account-1":
            return HealthCheckError(
                account_id=account_id, connector_id=connector_id, message="Test error", error_type=ErrorType.PERMISSION_ERROR
            )
        return None

    # Mock ThreadPoolExecutor to execute the function directly
    executor_mock = mocker.patch("COOCApiModule.ThreadPoolExecutor")
    executor_instance = executor_mock.return_value.__enter__.return_value

    # Set up the submit method to call our function directly
    def submit_side_effect(func, account, connector_id, check_func):
        future = mocker.MagicMock()
        result = func(account, connector_id, check_func)
        future.result.return_value = result
        return future

    executor_instance.submit.side_effect = submit_side_effect

    # Mock as_completed to return our futures
    future1 = mocker.MagicMock()
    future1.result.return_value = "error1"
    future2 = mocker.MagicMock()
    future2.result.return_value = None
    mocker.patch("COOCApiModule.as_completed", return_value=[future1, future2])

    # Call function
    result = run_permissions_check_for_accounts(connector_id="test-connector-id", permission_check_func=mock_permission_check)

    # Verify results
    assert result == "health_check_result"
    # Verify error was added to health check
    assert mock_health_check.error.called


def test_run_permissions_check_no_accounts(mocker):
    """
    Given: A connector_id with no associated accounts.
    When: run_permissions_check_for_accounts is called.
    Then: It returns "ok" without running any permission checks.
    """
    import demistomock as demisto
    from COOCApiModule import run_permissions_check_for_accounts, HealthStatus

    # Mock get_accounts_by_connector_id to return empty list
    mocker.patch("COOCApiModule.get_accounts_by_connector_id", return_value=[])
    mocker.patch.object(demisto, "debug")

    # Call function
    result = run_permissions_check_for_accounts(connector_id="test-connector-id", permission_check_func=mocker.Mock())

    # Verify results
    assert result == HealthStatus.OK
    assert demisto.debug.called
