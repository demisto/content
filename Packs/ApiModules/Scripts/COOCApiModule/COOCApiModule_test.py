
def test_get_cloud_entities_with_connector_id(mocker):
    """
    Given: A connector_id is provided to retrieve accounts associated with it.
    When: The get_cloud_entities function is called with a connector_id.
    Then: The function should make the correct API call and return the response.
    """
    # Mock response
    mock_response = {
        "status_code": 200,
        "data": '{"accounts": [{"id": "123", "name": "test-account"}]}'
    }

    # Mock the platform API call
    mock_platform_call = mocker.patch('demisto._platformAPICall', return_value=mock_response)

    # Call the function
    result = get_cloud_entities(connector_id="test-connector")

    # Assert API was called with the correct parameters
    mock_platform_call.assert_called_once_with(
        path=GET_ONBOARDING_ACCOUNTS,
        method="GET",
        params={
            "entity_type": "account",
            "entity_id": "test-connector"
        }
    )

    # Assert the result is the expected response
    assert result == mock_response


def test_get_cloud_entities_with_account_id(mocker):
    """
    Given: An account_id is provided to retrieve connectors associated with it.
    When: The get_cloud_entities function is called with an account_id.
    Then: The function should make the correct API call and return the response.
    """
    # Mock response
    mock_response = {
        "status_code": 200,
        "data": '{"connectors": [{"id": "456", "name": "test-connector"}]}'
    }

    # Mock the platform API call
    mock_platform_call = mocker.patch('demisto._platformAPICall', return_value=mock_response)

    # Call the function
    result = get_cloud_entities(account_id="test-account")

    # Assert API was called with the correct parameters
    mock_platform_call.assert_called_once_with(
        path=GET_ONBOARDING_CONNECTORS,
        method="GET",
        params={
            "entity_type": "connector",
            "entity_id": "test-account"
        }
    )

    # Assert the result is the expected response
    assert result == mock_response


def test_get_cloud_entities_with_error_response(mocker):
    """
    Given: An API call that returns an error status code.
    When: The get_cloud_entities function is called and the API returns a non-200 status code.
    Then: The function should raise a DemistoException with appropriate error message.
    """
    # Mock error response
    mock_response = {
        "status_code": 404,
        "data": "Resource not found"
    }

    # Mock the platform API call
    mocker.patch('demisto._platformAPICall', return_value=mock_response)

    # Call the function and expect an exception
    with pytest.raises(DemistoException) as e:
        get_cloud_entities(connector_id="test-connector")

    # Check the exception message
    assert "Failed to get accounts for ID 'test-connector'" in str(e.value)
    assert "Status code: 404" in str(e.value)
    assert "Detail: Resource not found" in str(e.value)


def test_get_cloud_entities_with_no_id(mocker):
    """
    Given: No connector_id or account_id is provided.
    When: The get_cloud_entities function is called without required parameters.
    Then: The function should raise a ValueError with appropriate error message.
    """
    # Call the function and expect an exception
    with pytest.raises(ValueError) as e:
        get_cloud_entities()

    # Check the exception message
    assert "Exactly one of connector_id or account_id must be provided" in str(e.value)


def test_get_cloud_entities_with_both_ids(mocker):
    """
    Given: Both connector_id and account_id are provided.
    When: The get_cloud_entities function is called with both parameters.
    Then: The function should raise a ValueError with appropriate error message.
    """
    # Call the function and expect an exception
    with pytest.raises(ValueError) as e:
        get_cloud_entities(connector_id="test-connector", account_id="test-account")

    # Check the exception message
    assert "Exactly one of connector_id or account_id must be provided" in str(e.value)


def test_get_access_token_success(mocker):
    """
    Given: A request for an access token for AWS cloud provider.
    When: The platform API call returns a successful response with a valid access token.
    Then: The function returns the access token string.
    """
    # Mock the calling context
    mock_context = {
        "connector_id": "test-connector-id",
        "account_id": "test-account-id",
        "outpost_id": "test-outpost-id",
        "region_name": "us-west-2"
    }
    mocker.patch('demistomock.callingContext', return_value={"context": mock_context})

    # Mock the platform API call response
    mock_response = {
        "status_code": 200,
        "data": json.dumps({"access_token": "test-access-token"})
    }
    mocker.patch('demistomock._platformAPICall', return_value=mock_response)

    # Execute function
    token = get_access_token(CloudTypes.AWS.value)

    # Assert results
    assert token == "test-access-token"

    # Verify the API was called with correct parameters
    expected_request_data = {
        "connector_id": "test-connector-id",
        "account_id": "test-account-id",
        "outpost_id": "test-outpost-id",
        "cloud_type": CloudTypes.AWS.value,
        "scopes": [],
        "region_name": "us-west-2"
    }
    mocker.patch('demistomock._platformAPICall').assert_called_once_with(
        path=GET_CTS_ACCOUNTS_TOKEN,
        method="POST",
        data=json.dumps({"request_data": expected_request_data})
    )


def test_get_access_token_with_scopes(mocker):
    """
    Given: A request for an access token for GCP cloud provider with specific scopes.
    When: The platform API call returns a successful response with a valid access token.
    Then: The function returns the access token string and includes the specified scopes in the request.
    """
    # Mock the calling context
    mock_context = {
        "connector_id": "test-connector-id",
        "account_id": "test-account-id",
        "outpost_id": "test-outpost-id"
    }
    mocker.patch('demistomock.callingContext', return_value={"context": mock_context})

    # Mock the platform API call response
    mock_response = {
        "status_code": 200,
        "data": json.dumps({"access_token": "test-gcp-token"})
    }
    mocker.patch('demistomock._platformAPICall', return_value=mock_response)

    # Test scopes
    test_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    # Execute function
    token = get_access_token(CloudTypes.GCP.value, test_scopes)

    # Assert results
    assert token == "test-gcp-token"

    # Verify the API was called with correct parameters
    expected_request_data = {
        "connector_id": "test-connector-id",
        "account_id": "test-account-id",
        "outpost_id": "test-outpost-id",
        "cloud_type": CloudTypes.GCP.value,
        "scopes": test_scopes
    }
    mocker.patch('demistomock._platformAPICall').assert_called_once_with(
        path=GET_CTS_ACCOUNTS_TOKEN,
        method="POST",
        data=json.dumps({"request_data": expected_request_data})
    )


def test_get_access_token_api_error(mocker):
    """
    Given: A request for an access token for AZURE cloud provider.
    When: The platform API call returns an error response with status code not equal to 200.
    Then: The function raises a DemistoException with appropriate error message.
    """
    # Mock the calling context
    mock_context = {
        "connector_id": "test-connector-id",
        "account_id": "test-account-id",
        "outpost_id": "test-outpost-id"
    }
    mocker.patch('demistomock.callingContext', return_value={"context": mock_context})

    # Mock the platform API call response with error
    mock_response = {
        "status_code": 400,
        "data": "Bad request: invalid parameters"
    }
    mocker.patch('demistomock._platformAPICall', return_value=mock_response)

    # Execute function and expect exception
    with pytest.raises(DemistoException) as excinfo:
        get_access_token(CloudTypes.AZURE.value)

    # Assert the error message
    error_message = f"Failed to get token from CTS for {CloudTypes.AZURE.value}. Status code: 400. Detail: Bad request: invalid parameters"
    assert str(excinfo.value) == error_message


def test_get_access_token_json_decode_error(mocker):
    """
    Given: A request for an access token for OCI cloud provider.
    When: The platform API call returns success response but with invalid JSON data.
    Then: The function raises a DemistoException about failing to parse the access token.
    """
    # Mock the calling context
    mock_context = {
        "connector_id": "test-connector-id",
        "account_id": "test-account-id",
        "outpost_id": "test-outpost-id"
    }
    mocker.patch('demistomock.callingContext', return_value={"context": mock_context})

    # Mock the platform API call response with invalid JSON
    mock_response = {
        "status_code": 200,
        "data": "{invalid json data"
    }
    mocker.patch('demistomock._platformAPICall', return_value=mock_response)

    # Execute function and expect exception
    with pytest.raises(DemistoException) as excinfo:
        get_access_token(CloudTypes.OCI.value)

    # Assert the error message
    assert f"Failed to parse access token from CTS response for {CloudTypes.OCI.value}" in str(excinfo.value)


def test_get_access_token_missing_key(mocker):
    """
    Given: A request for an access token for AWS cloud provider.
    When: The platform API call returns success response but the access_token key is missing.
    Then: The function raises a DemistoException about failing to parse the access token.
    """
    # Mock the calling context
    mock_context = {
        "connector_id": "test-connector-id",
        "account_id": "test-account-id",
        "outpost_id": "test-outpost-id"
    }
    mocker.patch('demistomock.callingContext', return_value={"context": mock_context})

    # Mock the platform API call response with missing access_token key
    mock_response = {
        "status_code": 200,
        "data": json.dumps({"token_type": "Bearer"})  # Missing access_token key
    }
    mocker.patch('demistomock._platformAPICall', return_value=mock_response)

    # Execute function and expect exception
    with pytest.raises(DemistoException) as excinfo:
        get_access_token(CloudTypes.AWS.value)

    # Assert the error message
    assert f"Failed to parse access token from CTS response for {CloudTypes.AWS.value}" in str(excinfo.value)