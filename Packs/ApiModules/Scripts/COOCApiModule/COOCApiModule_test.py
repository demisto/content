import json
import pytest
from CommonServerPython import DemistoException
from COOCApiModule import CloudTypes, get_cloud_credentials, get_cloud_entities


def test_get_cloud_credentials_success(mocker):
    """
    Given: A valid cloud type and calling context with required cloud information.
    When: The get_cloud_credentials function is called.
    Then: Function successfully returns the credentials dictionary from the platform API response.
    """
    # Import needed to avoid the ModuleNotFoundError
    import demistomock as demisto

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
    result = get_cloud_credentials(CloudTypes.AWS.value)

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
    # Import needed to avoid the ModuleNotFoundError
    import demistomock as demisto

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
    result = get_cloud_credentials(CloudTypes.GCP.value, scopes=test_scopes)

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
    # Import needed to avoid the ModuleNotFoundError
    import demistomock as demisto

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
        get_cloud_credentials(CloudTypes.AZURE.value)

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
    # Import needed to avoid the ModuleNotFoundError
    import demistomock as demisto

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
        get_cloud_credentials(CloudTypes.OCI.value)

    # Verify exception message
    assert "Failed to parse credentials from CTS response for OCI" in str(excinfo.value)


def test_get_cloud_entities_with_connector_id(mocker):
    """
    Given: A connector_id parameter.
    When: The get_cloud_entities function is called with the connector_id.
    Then: The function calls the platform API with the correct parameters and returns the response.
    """
    # Import needed to avoid the ModuleNotFoundError
    import demistomock as demisto

    # Mock platform API response
    api_response = {"status_code": 200, "data": {"accounts": [{"id": "account-1"}, {"id": "account-2"}]}}
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    # Call the function
    result = get_cloud_entities(connector_id="test-connector-id")

    # Verify API call was made with correct parameters
    call_args = demisto._platformAPICall.call_args[1]
    assert call_args["path"] == "/onboarding/accounts"
    assert call_args["method"] == "GET"
    assert call_args["params"] == {"entity_type": "account", "entity_id": "test-connector-id"}

    # Verify result
    assert result == api_response


def test_get_cloud_entities_with_account_id(mocker):
    """
    Given: An account_id parameter.
    When: The get_cloud_entities function is called with the account_id.
    Then: The function calls the platform API with the correct parameters and returns the response.
    """
    # Import needed to avoid the ModuleNotFoundError
    import demistomock as demisto

    # Mock platform API response
    api_response = {"status_code": 200, "data": {"connectors": [{"id": "connector-1"}, {"id": "connector-2"}]}}
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    # Call the function
    result = get_cloud_entities(account_id="test-account-id")

    # Verify API call was made with correct parameters
    call_args = demisto._platformAPICall.call_args[1]
    assert call_args["path"] == "/onboarding/connectors"
    assert call_args["method"] == "GET"
    assert call_args["params"] == {"entity_type": "connector", "entity_id": "test-account-id"}

    # Verify result
    assert result == api_response


def test_get_cloud_entities_api_error(mocker):
    """
    Given: A connector_id parameter but the API returns an error.
    When: The get_cloud_entities function is called.
    Then: A DemistoException is raised with the error details.
    """
    # Import needed to avoid the ModuleNotFoundError
    import demistomock as demisto

    # Mock platform API error response
    api_response = {"status_code": 404, "data": "Connector not found"}
    mocker.patch.object(demisto, "_platformAPICall", return_value=api_response)

    # Call the function and expect an exception
    with pytest.raises(DemistoException) as excinfo:
        get_cloud_entities(connector_id="test-connector-id")

    # Verify exception message
    assert "Failed to get accounts for ID 'test-connector-id'" in str(excinfo.value)
    assert "Status code: 404" in str(excinfo.value)
    assert "Detail: Connector not found" in str(excinfo.value)


def test_get_cloud_entities_invalid_params():
    """
    Given: No parameters or both connector_id and account_id parameters.
    When: The get_cloud_entities function is called.
    Then: A ValueError is raised indicating exactly one parameter must be provided.
    """
    # Test with no parameters
    with pytest.raises(ValueError) as excinfo:
        get_cloud_entities()
    assert "Exactly one of connector_id or account_id must be provided" in str(excinfo.value)

    # Test with both parameters
    with pytest.raises(ValueError) as excinfo:
        get_cloud_entities(connector_id="test-connector-id", account_id="test-account-id")
    assert "Exactly one of connector_id or account_id must be provided" in str(excinfo.value)
