from COOCApiModule import *
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import pytest


def test_get_access_token_success(mocker):
    """
    Given: A valid cloud type and scopes.
    When: The get_access_token function is called with these parameters.
    Then: The function should return the access token from the API response.
    """
    # Mock the callingContext as a property
    mock_context = {
        "context": {"connector_id": "test-connector-id", "account_id": "test-account-id", "outpost_id": "test-outpost-id"}
    }
    mocker.patch.object(demisto, "callingContext", mock_context)

    # Mock the platform API call
    mock_response = {"status_code": 200, "data": json.dumps({"access_token": "mock-access-token"})}
    mocker.patch.object(demisto, "_platformAPICall", return_value=mock_response)

    # Execute the function
    result = get_access_token("GCP", scopes=["https://www.googleapis.com/auth/cloud-platform"])

    # Assert the result
    assert result == "mock-access-token"
    demisto._platformAPICall.assert_called_once()


def test_get_access_token_aws_with_region(mocker):
    """
    Given: An AWS cloud type with region_name in the context.
    When: The get_access_token function is called.
    Then: The function should include region_name in the request data.
    """
    # Mock the callingContext as a property
    mock_context = {
        "context": {
            "connector_id": "test-connector-id",
            "account_id": "test-account-id",
            "outpost_id": "test-outpost-id",
            "region_name": "us-west-2",
        }
    }
    mocker.patch.object(demisto, "callingContext", mock_context)

    # Mock the platform API call
    mock_response = {"status_code": 200, "data": json.dumps({"access_token": "mock-aws-token"})}
    mocker.patch.object(demisto, "_platformAPICall", return_value=mock_response)

    # Execute the function
    result = get_access_token("AWS")

    # Assert the result
    assert result == "mock-aws-token"

    # Check that region_name was included in the request data
    call_args = demisto._platformAPICall.call_args[1]
    request_data = json.loads(call_args["data"])["request_data"]
    assert request_data["region_name"] == "us-west-2"


def test_get_access_token_error_response(mocker):
    """
    Given: A cloud type and an error response from the API.
    When: The get_access_token function is called.
    Then: The function should raise a DemistoException with the error details.
    """
    # Mock the callingContext as a property
    mock_context = {
        "context": {"connector_id": "test-connector-id", "account_id": "test-account-id", "outpost_id": "test-outpost-id"}
    }
    mocker.patch.object(demisto, "callingContext", mock_context)

    # Mock the platform API call
    mock_response = {"status_code": 403, "data": "Access denied"}
    mocker.patch.object(demisto, "_platformAPICall", return_value=mock_response)

    # Execute the function and expect an exception
    with pytest.raises(DemistoException) as e:
        get_access_token("GCP")

    # Assert the exception message
    assert "Failed to get token from CTS for GCP" in str(e.value)
    assert "Status code: 403" in str(e.value)
    assert "Detail: Access denied" in str(e.value)


def test_get_access_token_parse_error(mocker):
    """
    Given: A cloud type and an invalid JSON response.
    When: The get_access_token function is called.
    Then: The function should raise a DemistoException about parsing failure.
    """
    # Mock the callingContext as a property
    mock_context = {
        "context": {"connector_id": "test-connector-id", "account_id": "test-account-id", "outpost_id": "test-outpost-id"}
    }
    mocker.patch.object(demisto, "callingContext", mock_context)

    # Mock the platform API call with invalid JSON
    mock_response = {"status_code": 200, "data": "{invalid json"}
    mocker.patch.object(demisto, "_platformAPICall", return_value=mock_response)

    # Execute the function and expect an exception
    with pytest.raises(DemistoException) as e:
        get_access_token("GCP")

    # Assert the exception message
    assert "Failed to parse access token from CTS response for GCP" in str(e.value)


def test_get_access_token_missing_token(mocker):
    """
    Given: A cloud type and a response without the access_token key.
    When: The get_access_token function is called.
    Then: The function should raise a DemistoException about missing token.
    """
    # Mock the callingContext as a property
    mock_context = {
        "context": {"connector_id": "test-connector-id", "account_id": "test-account-id", "outpost_id": "test-outpost-id"}
    }
    mocker.patch.object(demisto, "callingContext", mock_context)

    # Mock the platform API call with missing token
    mock_response = {"status_code": 200, "data": json.dumps({"something_else": "value"})}
    mocker.patch.object(demisto, "_platformAPICall", return_value=mock_response)

    # Execute the function and expect an exception
    with pytest.raises(DemistoException) as e:
        get_access_token("GCP")

    # Assert the exception message
    assert "Failed to parse access token from CTS response for GCP" in str(e.value)


def test_get_cloud_entities_connector(mocker):
    """
    Given: A connector_id parameter.
    When: The get_cloud_entities function is called with this connector_id.
    Then: The function should return accounts associated with the connector.
    """
    # Mock the platform API call response
    mock_response = {"status_code": 200, "data": json.dumps({"accounts": [{"id": "account-1"}, {"id": "account-2"}]})}
    mocker.patch.object(demisto, "_platformAPICall", return_value=mock_response)

    # Execute the function
    result = get_cloud_entities(connector_id="connector-123")

    # Assert the result
    assert result == mock_response
    demisto._platformAPICall.assert_called_once_with(
        path=GET_ONBOARDING_ACCOUNTS, method="GET", params={"entity_type": "account", "entity_id": "connector-123"}
    )


def test_get_cloud_entities_account(mocker):
    """
    Given: An account_id parameter.
    When: The get_cloud_entities function is called with this account_id.
    Then: The function should return connectors associated with the account.
    """
    # Mock the platform API call response
    mock_response = {"status_code": 200, "data": json.dumps({"connectors": [{"id": "connector-1"}, {"id": "connector-2"}]})}
    mocker.patch.object(demisto, "_platformAPICall", return_value=mock_response)

    # Execute the function
    result = get_cloud_entities(account_id="account-123")

    # Assert the result
    assert result == mock_response
    demisto._platformAPICall.assert_called_once_with(
        path=GET_ONBOARDING_CONNECTORS, method="GET", params={"entity_type": "connector", "entity_id": "account-123"}
    )


def test_get_cloud_entities_validation_error():
    """
    Given: Neither connector_id nor account_id parameters provided, or both provided.
    When: The get_cloud_entities function is called.
    Then: The function should raise a ValueError.
    """
    # Case 1: Neither parameter provided
    with pytest.raises(ValueError) as e:
        get_cloud_entities()
    assert "Exactly one of connector_id or account_id must be provided" in str(e.value)

    # Case 2: Both parameters provided
    with pytest.raises(ValueError) as e:
        get_cloud_entities(connector_id="connector-123", account_id="account-123")
    assert "Exactly one of connector_id or account_id must be provided" in str(e.value)


def test_get_cloud_entities_api_error(mocker):
    """
    Given: A connector_id parameter and an error response from the API.
    When: The get_cloud_entities function is called.
    Then: The function should raise a DemistoException with the error details.
    """
    # Mock the platform API call with an error
    mock_response = {"status_code": 403, "data": "Permission denied"}
    mocker.patch.object(demisto, "_platformAPICall", return_value=mock_response)

    # Execute the function and expect an exception
    with pytest.raises(DemistoException) as e:
        get_cloud_entities(connector_id="connector-123")

    # Assert the exception message
    assert "Failed to get accounts for ID 'connector-123'" in str(e.value)
    assert "Status code: 403" in str(e.value)
    assert "Detail: Permission denied" in str(e.value)
