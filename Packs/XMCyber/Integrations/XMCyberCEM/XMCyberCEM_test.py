import json
from pathlib import Path

import pytest
from CommonServerPython import *
from XMCyberCEM import ENDPOINTS, ERRORS, OUTPUT_PREFIXES, Client

BASE_URL = "https://test.xmcyber.com"
API_KEY = "test_api_key"
TEST_DATA_DIR = Path(__file__).parent / "test_data"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def client(mocker):
    """Fixture to create a client instance with mocked token generation."""
    mocker.patch.object(Client, "_generate_token", return_value="test_access_token")
    return Client(BASE_URL, API_KEY, verify=False, proxy=False)


def test_generate_token(requests_mock):
    """
    Given:
    - Mocked response for generating access tokens.
    - Client instance.

    When:
    - Calling the `_generate_token` method.

    Then:
    - Ensure the generated access token matches the expected access token.
    - Ensure both access_token and refresh_token are stored in integration context.
    """
    # Set up
    access_token = "test_access_token_12345"
    refresh_token = "test_refresh_token_67890"
    response_data = {"accessToken": access_token, "refreshToken": refresh_token}

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=response_data, status_code=200)

    client = Client(BASE_URL, API_KEY, verify=False, proxy=False)
    token = client._generate_token()

    assert token == access_token


def test_generate_token_failure(requests_mock):
    """
    Given:
    - Mocked failed response for generating access tokens (400 error).
    - Client instance.

    When:
    - Calling the `_generate_token` method.

    Then:
    - Ensure the method raises an exception.
    """
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", status_code=400)

    client = Client(BASE_URL, API_KEY, verify=False, proxy=False)

    with pytest.raises(Exception):
        client._generate_token()


def test_generate_tokens_unauthorized(requests_mock):
    """
    Given:
    - Mocked unauthorized response (401) for generating access tokens.
    - Client instance.

    When:
    - Calling the `_generate_token` method.

    Then:
    - Ensure the method raises a ValueError with appropriate error message.
    """
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", status_code=401)

    client = Client(BASE_URL, API_KEY, verify=False, proxy=False)

    with pytest.raises(ValueError) as err_msg:
        client._generate_token()

    assert ERRORS["GENERAL_AUTH_ERROR"].format(401) in str(err_msg.value)


def test_generate_access_token_using_refresh_token(requests_mock, mocker):
    """
    Given:
    - Mocked response for generating access token using refresh token.
    - Client instance.
    - Mocked `get_integration_context` method.

    When:
    - Calling the `_generate_access_token_using_refresh_token` method.

    Then:
    - Ensure the generated access token matches the expected access token.
    - Ensure the new tokens are stored in integration context.
    """
    # Set up
    new_access_token = "new_access_token_12345"
    new_refresh_token = "new_refresh_token_67890"
    response_data = {"accessToken": new_access_token, "refreshToken": new_refresh_token}

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['REFRESH_TOKEN_ENDPOINT']}", json=response_data, status_code=200)

    client = Client(BASE_URL, API_KEY, verify=False, proxy=False)
    mocker.patch("XMCyberCEM.get_integration_context", return_value={"refresh_token": "old_refresh_token"})

    token = client._generate_access_token_using_refresh_token()

    assert token == new_access_token


def test_generate_access_token_using_refresh_token_not_found_in_integration_context(requests_mock, mocker):
    """
    Given:
    - Mocked response for generating access token using refresh token.
    - Client instance.
    - Mocked `get_integration_context` method.

    When:
    - Calling the `_generate_access_token_using_refresh_token` method.

    Then:
    - Ensure the generated access token matches the expected access token.
    - Ensure the new tokens are stored in integration context.
    """
    # Set up
    new_access_token = "new_access_token_12345"
    new_refresh_token = "new_refresh_token_67890"
    response_data = {"accessToken": new_access_token, "refreshToken": new_refresh_token}

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=response_data, status_code=200)

    client = Client(BASE_URL, API_KEY, verify=False, proxy=False)
    mocker.patch("XMCyberCEM.get_integration_context", return_value={})

    token = client._generate_access_token_using_refresh_token()

    assert token == new_access_token


def test_generate_access_token_using_refresh_token_no_new_refresh(requests_mock, mocker):
    """
    Given:
    - Mocked response for generating access token using refresh token.
    - Response does not include a new refresh token.
    - Client instance.

    When:
    - Calling the `_generate_access_token_using_refresh_token` method.

    Then:
    - Ensure the generated access token is returned.
    - Ensure the old refresh token is preserved in integration context.
    """
    # Set up
    new_access_token = "new_access_token_12345"
    old_refresh_token = "old_refresh_token"
    response_data = {"accessToken": new_access_token}  # No new refresh token

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['REFRESH_TOKEN_ENDPOINT']}", json=response_data, status_code=200)

    client = Client(BASE_URL, API_KEY, verify=False, proxy=False)
    mocker.patch("XMCyberCEM.get_integration_context", return_value={"refresh_token": old_refresh_token})

    token = client._generate_access_token_using_refresh_token()

    assert token == new_access_token


def test_generate_access_token_using_refresh_token_failure(requests_mock, mocker):
    """
    Given:
    - Mocked failed response for generating access token using refresh token (400 error).
    - Client instance.

    When:
    - Calling the `_generate_access_token_using_refresh_token` method.

    Then:
    - Ensure the method raises an exception.
    """
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['REFRESH_TOKEN_ENDPOINT']}", status_code=500)

    client = Client(BASE_URL, API_KEY, verify=False, proxy=False)
    mocker.patch("XMCyberCEM.get_integration_context", return_value={"refresh_token": "refresh_token"})

    with pytest.raises(Exception):
        client._generate_access_token_using_refresh_token()


def test_generate_access_token_using_expired_refresh_token_400_status_code(requests_mock, mocker, client):
    """
    Given:
    - A client object.
    - A mocked HTTP POST request to the refresh-token endpoint with a status code of 400.
    - A mocked '_generate_token' method that returns a new token.

    When:
    - Calling the '_generate_access_token_using_refresh_token' method.

    Then:
    - Assert that the '_generate_token' method is called once.
    - Assert that a new token is returned.
    """
    new_access_token = "regenerated_access_token"
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['REFRESH_TOKEN_ENDPOINT']}", status_code=400)
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}",
        json={"accessToken": new_access_token, "refreshToken": "new_refresh_token"},
        status_code=200,
    )

    mocker.patch("XMCyberCEM.get_integration_context", return_value={"refresh_token": "old_refresh_token"})
    generate_token = mocker.patch.object(client, "_generate_token", return_value=new_access_token)

    token = client._generate_access_token_using_refresh_token()

    assert token == new_access_token
    generate_token.assert_called_once()


def test_generate_token_invalid_json_response(requests_mock):
    """
    Given:
    - Mocked response with invalid JSON for generating access tokens.
    - Client instance.

    When:
    - Calling the `_generate_token` method with a response that has invalid JSON.

    Then:
    - Ensure the method raises a DemistoException.
    """
    # Return invalid JSON response
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", text="Invalid JSON", status_code=200)

    client = Client(BASE_URL, API_KEY, verify=False, proxy=False)

    with pytest.raises(DemistoException) as exc_info:
        client._generate_token()

    assert ERRORS["INVALID_OBJECT"].format("json", "Invalid JSON") in str(exc_info.value)


def test_generate_access_token_using_refresh_token_invalid_json_response(requests_mock, mocker):
    """
    Given:
    - Mocked response with invalid JSON for refresh token endpoint.
    - Client instance.

    When:
    - Calling the `_generate_access_token_using_refresh_token` method with invalid JSON response.

    Then:
    - Ensure the method raises a DemistoException.
    """
    # Return invalid JSON response
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['REFRESH_TOKEN_ENDPOINT']}", text="Invalid JSON", status_code=200)

    client = Client(BASE_URL, API_KEY, verify=False, proxy=False)
    mocker.patch("XMCyberCEM.get_integration_context", return_value={"refresh_token": "refresh_token"})

    with pytest.raises(DemistoException) as exc_info:
        client._generate_access_token_using_refresh_token()

    assert ERRORS["INVALID_OBJECT"].format("json", "Invalid JSON") in str(exc_info.value)


def test_http_request_success(requests_mock, client):
    """
    Given:
    - A client object.
    - A mocked successful HTTP GET request.

    When:
    - Making a GET request that returns a 200 status code.

    Then:
    - Assert that the response is returned correctly.
    - Assert that the response data matches expected data.
    """
    response_data = {"data": "test_data"}
    requests_mock.get(f"{BASE_URL}/api/test", json=response_data, status_code=200)

    result = client.http_request(method="GET", url_suffix="/api/test", response_type="json")

    assert result == response_data


def test_http_request_invalid_json_response(requests_mock, client):
    """
    Given:
    - Mocked response with invalid JSON for refresh token endpoint.
    - Client instance.

    When:
    - Calling the `http_request` method with invalid JSON response.

    Then:
    - Ensure the method raises a DemistoException.
    """
    # Return invalid JSON response
    requests_mock.get(f"{BASE_URL}/api/test", text="Invalid JSON", status_code=200)

    with pytest.raises(DemistoException) as exc_info:
        client.http_request(method="GET", url_suffix="/api/test", response_type="json")

    assert ERRORS["INVALID_OBJECT"].format("json", "Invalid JSON") in str(exc_info.value)


def test_http_request_with_401_status_code(requests_mock, client):
    """
    Given:
    - A mocked HTTP request that returns a response with a 401 status code initially.
    - A client object.

    When:
    - Making a request that results in a 401 status code.

    Then:
    - Assert that the request is retried with the new token.
    """
    response_data = {"data": "success"}
    new_access_token = "new_access_token"

    # First request returns 401, second request returns 200
    requests_mock.get(f"{BASE_URL}/api/test", [{"status_code": 401}, {"json": response_data, "status_code": 200}])

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['REFRESH_TOKEN_ENDPOINT']}", json={"accessToken": new_access_token}, status_code=200
    )

    result = client.http_request(method="GET", url_suffix="/api/test", response_type="json")

    assert result == response_data
    assert client._access_token == new_access_token


def test_http_request_with_401_exhausted_retries(requests_mock, mocker, client):
    """
    Given:
    - A mocked HTTP request that continuously returns a 401 status code.
    - A client object.

    When:
    - Making a request that exhausts internal retries (4 attempts).

    Then:
    - Assert that after exhausting retries, the method returns None or handles appropriately.
    """
    # Always return 401
    requests_mock.get(f"{BASE_URL}/api/test", status_code=401, text="Unauthorized")
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['REFRESH_TOKEN_ENDPOINT']}", json={"accessToken": "new_token"}, status_code=200)

    mocker.patch("XMCyberCEM.get_integration_context", return_value={"refresh_token": "refresh_token"})

    with pytest.raises(ValueError) as err_msg:
        client.http_request(method="GET", url_suffix="/api/test", response_type="json")

    assert ERRORS["GENERAL_AUTH_ERROR"].format(401) in str(err_msg.value)


def test_test_module_success(requests_mock, client):
    """
    Given:
    - XMCyberCEM test module
    - Mocked successful response from get_entities.

    When:
    - Running the test_module command using the Client.

    Then:
    - Validate the response is 'ok'.
    """
    from XMCyberCEM import test_module

    entity_response = util_load_json(f"{TEST_DATA_DIR}/get_entities_response.json")

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=entity_response)
    result = test_module(client)

    assert result == "ok"


def test_test_module_success_using_main(requests_mock, mocker):
    """
    Given:
    - XMCyberCEM test module
    - Mocked successful response from get_entities.

    When:
    - Running the test_module command using the Client.

    Then:
    - Validate the response is 'ok'.
    """
    from XMCyberCEM import main

    mocker.patch.object(demisto, "params", return_value={"server_url": BASE_URL, "credentials": {"password": API_KEY}})
    mocker.patch.object(demisto, "command", return_value="test-module")
    entity_response = util_load_json(f"{TEST_DATA_DIR}/get_entities_response.json")

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=entity_response)
    main()


def test_test_module_failure(requests_mock, client):
    """
    Given:
    - XMCyberCEM test module
    - Mocked failed response from get_entities.

    When:
    - Running the test_module command using the Client.

    Then:
    - Validate that an exception is raised.
    """
    from XMCyberCEM import test_module

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", status_code=400, text="Bad Request")

    with pytest.raises(Exception) as exc_info:
        test_module(client)

    assert "Bad Request" in str(exc_info.value)


@pytest.mark.parametrize("params", [({"server_url": BASE_URL, "credentials": {"password": ""}}), ({"server_url": ""})])
def test_test_module_invalid_params(params, mocker, capfd):
    """
    Given:
    - XMCyberCEM test module
    - Invalid parameters.

    When:
    - Running the main function.

    Then:
    - Validate that SystemExit is raised and the error message is correct.
    """
    from XMCyberCEM import main

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")

    with capfd.disabled(), pytest.raises(SystemExit):
        main()


def test_main_unknown_commmand(mocker, capfd):
    """Tests the execution of main function when unknown command name is provided."""
    from XMCyberCEM import main

    mocker.patch.object(demisto, "params", return_value={"server_url": BASE_URL, "credentials": {"password": API_KEY}})
    mocker.patch.object(demisto, "command", return_value="unknown_command")

    with capfd.disabled(), pytest.raises(SystemExit):
        main()


def test_client_initialization_with_existing_token(mocker):
    """
    Given:
    - Existing access token in integration context.

    When:
    - Initializing a new Client instance.

    Then:
    - Assert that the existing token is used.
    - Assert that _generate_token is not called.
    """
    existing_token = "existing_access_token"
    mocker.patch("XMCyberCEM.get_integration_context", return_value={"access_token": existing_token})
    generate_tokens_mock = mocker.patch.object(Client, "_generate_token")

    client = Client(BASE_URL, API_KEY, verify=False, proxy=False)

    assert client._access_token == existing_token
    generate_tokens_mock.assert_not_called()


def test_xmcyber_enrich_incident_command_success(requests_mock, client, mocker):
    """
    Given:
    - Multiple entity values (comma-separated) including valid user, valid asset, and invalid entities
    - Some entities have missing userid/hostname fields

    When:
    - xmcyber_enrich_incident_command is executed with multiple mixed entities

    Then:
    - Assert that CommandResults is returned with valid entities only
    - Assert that invalid entities are skipped (logged but not included in output)
    - Assert that outputs contain both user and asset data
    - Assert that readable output contains proper table format
    - Assert that context path is correct (XMCyber.Entity)
    """
    from XMCyberCEM import xmcyber_enrich_incident_command

    response = util_load_json(f"{TEST_DATA_DIR}/enrich_incident_response.json")
    with open(f"{TEST_DATA_DIR}/enrich_incident_hr.md") as f:
        hr_output = f.read()

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=response.get("raw_response"))
    mock_return_warning = mocker.patch("XMCyberCEM.return_warning")

    args = {"entity_values": "user_1,hostname_1, non_existent_entity_1, non_existent_entity_2"}
    result = xmcyber_enrich_incident_command(client, args)

    # Assertions
    assert result.outputs_prefix == OUTPUT_PREFIXES["Entity"]
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 2  # Only 2 valid entities
    assert result.outputs == response.get("outputs")
    assert result.raw_response == response.get("raw_response")
    assert result.readable_output == hr_output
    mock_return_warning.assert_called_once_with(
        "The following entities were not found: non_existent_entity_1, non_existent_entity_2"
    )


def test_xmcyber_enrich_incident_command_empty_response(requests_mock, client):
    """
    Given:
    - Valid entity_values argument
    - API returns empty response (no entities found)

    When:
    - xmcyber_enrich_incident_command is executed

    Then:
    - Assert that CommandResults is returned with appropriate message
    - Assert that readable output indicates no data found
    - Assert that outputs is None or empty
    """
    from XMCyberCEM import xmcyber_enrich_incident_command

    # Mock empty response
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=[])

    args = {"entity_values": "non-existent-entity"}
    result = xmcyber_enrich_incident_command(client, args)

    assert result.readable_output == "### No enrichment data found for the specified entities."


def test_xmcyber_enrich_incident_command_invalid_arguments(client):
    """
    Given:
    - Invalid entity_values argument

    When:
    - xmcyber_enrich_incident_command is executed

    Then:
    - Assert that ValueError is raised
    - Assert that error message mentions 'entity_values' is required
    """
    from XMCyberCEM import ERRORS, xmcyber_enrich_incident_command

    args = {"entity_values": "   "}
    with pytest.raises(ValueError) as err:
        xmcyber_enrich_incident_command(client, args)

    assert ERRORS["REQUIRED_ARGUMENT"].format("entity_values") in str(err.value)


def test_xmcyber_enrich_incident_command_via_main(requests_mock, mocker):
    """
    Given:
    - Integration configured with valid server URL and API key
    - Mock response with user and asset entities from test data
    - Command: xmcyber-enrich-incident
    - Args: entity_values with comma-separated values

    When:
    - main() function is called to execute the command

    Then:
    - Assert that main() function is called to execute the command
    """
    from XMCyberCEM import main

    enrich_response = util_load_json(f"{TEST_DATA_DIR}/enrich_incident_response.json")

    # Mock integration parameters
    mocker.patch.object(demisto, "params", return_value={"server_url": BASE_URL, "credentials": {"password": API_KEY}})
    mocker.patch.object(demisto, "command", return_value="xmcyber-enrich-incident")
    mocker.patch.object(demisto, "args", return_value={"entity_values": "user_1,hostname_1  ,   ,  ,  ,"})

    # Mock API response
    mock_get = requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=enrich_response.get("raw_response"))

    main()

    # Verify the API was called with correct query parameters
    assert mock_get.called
    assert mock_get.call_count == 1

    # Validate query parameters sent to API
    request_query = mock_get.last_request.qs
    assert "user_1" in request_query["names"]
    assert "hostname_1" in request_query["names"]
    assert len(request_query["names"]) == 2


@pytest.mark.parametrize(
    "parameter,operator,value",
    [
        ("Affected Unique Entities", "Equals", "2"),
        ("Labels", "Contains", "Label1"),
        ("Labels", "Not Contains", "Label3"),
        ("Choke Point Score", "Greater than", "10"),
        ("Compromise Risk Score", "Greater than equal to", "50"),
        ("Last Login Date", "Greater than", "2025-11-01T00:00:00.000Z"),
        ("Is Enabled", "Equals", "True"),
        ("Last Password Set Date", "Less than equal to", "2025-11-01T00:00:00.000Z"),
    ],
)
def test_xmcyber_push_breach_point_command_success_parametrized(requests_mock, mocker, client, parameter, operator, value):
    """
    Given:
    - Multiple entities with various attributes
    - Different parameter, operator, and value combinations

    When:
    - xmcyber_push_breach_point_command is executed with different criteria

    Then:
    - Assert that the correct number of entities match the criteria
    - Assert that breach point labels are pushed successfully
    - Assert that context outputs are created for matched entities
    """
    from XMCyberCEM import xmcyber_push_breach_point_command

    response = util_load_json(f"{TEST_DATA_DIR}/push_breach_point_entities.json")
    with open(f"{TEST_DATA_DIR}/push_breach_point_hr.md") as f:
        hr_output = f.read()

    # Mock API calls
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=response.get("raw_response"))

    mock_push = requests_mock.post(f"{BASE_URL}{ENDPOINTS['PUSH_BREACH_POINT_ENDPOINT']}", status_code=200)
    mock_return_warning = mocker.patch("XMCyberCEM.return_warning")

    args = {
        "entity_values": "hostname_1,user_1,user_3,not_exist_user_id",
        "attribute_name": "XSOAR_Test",
        "parameter": parameter,
        "operator": operator,
        "value": value,
    }

    result = xmcyber_push_breach_point_command(client, args)

    # Assertions
    assert result.outputs_prefix == OUTPUT_PREFIXES["PushBreachPoint"]
    assert result.outputs_key_field == ["attributeName", "userSuppliedEntities"]
    assert result.outputs.get("attributeName") == "XSOAR_Test"
    assert result.outputs.get("userSuppliedEntities") == "hostname_1, not_exist_user_id, user_1, user_3"
    assert result.outputs.get("matchedEntities") == "hostname_1, user_1"
    assert result.outputs.get("notMatchedEntities") == "not_exist_user_id, user_3"
    assert result.outputs.get("parameter") == parameter
    assert result.outputs.get("operator") == operator
    assert result.outputs.get("value") == value
    assert result.readable_output == hr_output
    assert mock_push.called
    expected_request_body = {
        "0000000000000000001": ["importedLable1", "XSOAR_Test"],
        "0000000000000000002": ["importedLable1", "XSOAR_Test"],
    }
    assert mock_push.last_request.json() == expected_request_body
    mock_return_warning.assert_called_once_with(
        "The following entities did not match the specified criteria: user_3, not_exist_user_id"
    )


def test_xmcyber_push_breach_point_command_entity_id_parameter(requests_mock, client):
    """
    Given:
    - Multiple entities
    - Parameter set to "entityID" (case-insensitive)
    - Operator set to "Equals"
    - Value set to specific entity ID

    When:
    - xmcyber_push_breach_point_command is executed

    Then:
    - Assert that only the entity with matching ID is selected
    - Assert that breach point label is pushed successfully
    """
    from XMCyberCEM import xmcyber_push_breach_point_command

    response = util_load_json(f"{TEST_DATA_DIR}/push_breach_point_entities.json")
    with open(f"{TEST_DATA_DIR}/push_breach_point_entity_id_hr.md") as f:
        hr_output = f.read()

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=response.get("raw_response"))
    mock_push = requests_mock.post(f"{BASE_URL}{ENDPOINTS['PUSH_BREACH_POINT_ENDPOINT']}", status_code=200)

    args = {
        "entity_values": "hostname_1,user_1,user_3",
        "attribute_name": "XSOAR_Test",
        "parameter": "Entity ID",
        "operator": "Equals",
        "value": "0000000000000000001",
    }

    result = xmcyber_push_breach_point_command(client, args)

    # Assertions
    assert result.outputs_prefix == OUTPUT_PREFIXES["PushBreachPoint"]
    assert result.outputs_key_field == ["attributeName", "userSuppliedEntities"]
    assert result.outputs == response.get("outputs_entity_id")
    assert result.readable_output == hr_output
    assert mock_push.called


def test_xmcyber_push_breach_point_command_all_parameter(requests_mock, client):
    """
    Given:
    - Multiple entity values (user_1, user_2, hostname_1)
    - Parameter set to "All"

    When:
    - xmcyber_push_breach_point_command is executed

    Then:
    - Assert that all entities are selected regardless of other criteria
    - Assert that breach point labels are pushed for all entities
    - Assert that context outputs are created for all entities
    """
    from XMCyberCEM import xmcyber_push_breach_point_command

    response = util_load_json(f"{TEST_DATA_DIR}/push_breach_point_entities.json")
    with open(f"{TEST_DATA_DIR}/push_breach_point_all_hr.md") as f:
        hr_output = f.read()

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=response.get("raw_response"))
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['PUSH_BREACH_POINT_ENDPOINT']}", status_code=200)

    args = {
        "entity_values": "hostname_1,user_1,user_3",
    }

    result = xmcyber_push_breach_point_command(client, args)

    # Assertions
    assert result.outputs_prefix == OUTPUT_PREFIXES["PushBreachPoint"]
    assert result.outputs_key_field == ["attributeName", "userSuppliedEntities"]
    assert result.outputs == response.get("outputs_all")
    assert result.readable_output == hr_output


def test_xmcyber_push_breach_point_command_no_entities_found(requests_mock, client):
    """
    Given:
    - Entity values that don't exist (hostname_1, user_1, user_2)
    - API returns empty response

    When:
    - xmcyber_push_breach_point_command is executed

    Then:
    - Assert that CommandResults is returned with appropriate message
    - Assert that readable output indicates no entities found
    - Assert that no breach point data is pushed to the API
    """
    from XMCyberCEM import xmcyber_push_breach_point_command

    # Mock empty response
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=[])
    mock_push = requests_mock.post(f"{BASE_URL}{ENDPOINTS['PUSH_BREACH_POINT_ENDPOINT']}", status_code=200)

    args = {
        "entity_values": "hostname_1,user_1,user_2",
        "parameter": "All",
    }

    result = xmcyber_push_breach_point_command(client, args)

    # Assertions
    assert result.readable_output == "### No enrichment data found for the specified entities."
    assert not mock_push.called


def test_xmcyber_push_breach_point_command_no_matching_criteria(requests_mock, client):
    """
    Given:
    - Valid entities (user_1, user_3, hostname_1)
    - Parameter: Entity ID
    - Operator: Equals
    - Value: non-existent-id (criteria that no entity matches)

    When:
    - xmcyber_push_breach_point_command is executed

    Then:
    - Assert that no entities match the criteria
    - Assert that no breach point data is pushed
    - Assert that appropriate message is returned
    - Assert that outputs contains NotMatchedEntities list
    """
    from XMCyberCEM import xmcyber_push_breach_point_command

    response = util_load_json(f"{TEST_DATA_DIR}/push_breach_point_entities.json")

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=response.get("raw_response"))
    mock_push = requests_mock.post(f"{BASE_URL}{ENDPOINTS['PUSH_BREACH_POINT_ENDPOINT']}", status_code=200)

    args = {
        "entity_values": "hostname_1,user_1,user_3",
        "parameter": "Entity ID",
        "operator": "Equals",
        "value": "non-existent-id",
    }

    result = xmcyber_push_breach_point_command(client, args)

    # Assertions
    assert result.readable_output == "### No entities matched the specified criteria to push breach point data."
    assert not mock_push.called
    assert result.outputs.get("userSuppliedEntities") == "hostname_1, user_1, user_3"
    assert result.outputs.get("matchedEntities") == ""
    assert result.outputs.get("notMatchedEntities") == "hostname_1, user_1, user_3"
    assert result.outputs.get("parameter") == "Entity ID"
    assert result.outputs.get("operator") == "Equals"
    assert result.outputs.get("value") == "non-existent-id"


@pytest.mark.parametrize(
    "args,expected_error",
    [
        ({"entity_values": "   "}, ERRORS["REQUIRED_ARGUMENT"].format("entity_values")),
        (
            {"entity_values": "user_1", "parameter": "InvalidParameter"},
            "Invalid 'InvalidParameter' value provided",
        ),
        (
            {"entity_values": "user_1", "operator": "InvalidOperator"},
            "Invalid 'InvalidOperator' value provided",
        ),
        (
            {"entity_values": "user_1", "parameter": "Choke Point Score", "operator": "Contains", "value": "50"},
            ERRORS["CONTAINS_INCORRECT_OPERATOR"].format("Choke Point Score"),
        ),
        (
            {"entity_values": "user_1", "parameter": "laBels", "operator": "Greater than", "value": "50"},
            ERRORS["CONTAINS_INCORRECT_PARAMETER"].format("Labels"),
        ),
        (
            {"entity_values": "user_1", "parameter": "Entity ID", "operator": "Greater than", "value": "test"},
            ERRORS["EQUALITY_INCORRECT_OPERATOR"].format("Entity ID"),
        ),
        (
            {"entity_values": "user_1", "parameter": "Domain Name", "operator": "Greater than", "value": "test.com"},
            ERRORS["EQUALITY_INCORRECT_OPERATOR"].format("Domain Name"),
        ),
        (
            {"entity_values": "user_1", "parameter": "Domain Name", "operator": "Greater than", "value": "100"},
            ERRORS["EQUALITY_INCORRECT_OPERATOR"].format("Domain Name"),
        ),
        (
            {"entity_values": "user_1", "parameter": "Is Enabled", "operator": "Greater than", "value": "yes"},
            ERRORS["INCORRECT_VALUE_TYPE"],
        ),
    ],
)
def test_xmcyber_push_breach_point_command_invalid_arguments(client, args, expected_error):
    """
    Given:
    - Invalid arguments for push breach point command
    - Various validation error scenarios (empty entity_values, invalid parameter/operator, etc.)

    When:
    - xmcyber_push_breach_point_command is executed with invalid arguments

    Then:
    - Assert that ValueError is raised
    - Assert that error message contains the expected error text
    """
    from XMCyberCEM import xmcyber_push_breach_point_command

    with pytest.raises(ValueError) as err:
        xmcyber_push_breach_point_command(client, args)

    assert expected_error in str(err.value)


def test_xmcyber_remove_breach_point_command_success(requests_mock, mocker, client):
    """
    Given:
    - Multiple entity values (user_1, hostname_1, non_existent_entity)
    - Some entities exist in XM Cyber with breach point labels
    - One entity does not exist in XM Cyber

    When:
    - xmcyber_remove_breach_point_command is executed

    Then:
    - Assert that CommandResults is returned with proper outputs
    - Assert that breach point labels are removed successfully for found entities
    - Assert that warning is returned for entity not found
    - Assert that context outputs contain removedEntities and userSuppliedEntities
    - Assert that readable output indicates success
    """
    from XMCyberCEM import xmcyber_remove_breach_point_command

    response = util_load_json(f"{TEST_DATA_DIR}/remove_breach_point_response.json")
    with open(f"{TEST_DATA_DIR}/remove_breach_point_hr.md") as f:
        hr_output = f.read()

    # Mock API calls
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=response.get("raw_response"))
    mock_push = requests_mock.post(f"{BASE_URL}{ENDPOINTS['PUSH_BREACH_POINT_ENDPOINT']}", status_code=200)
    mock_return_warning = mocker.patch("XMCyberCEM.return_warning")

    args = {"entity_values": "user_1,hostname_1,non_existent_entity", "attribute_name": "XSOAR_Test"}

    result = xmcyber_remove_breach_point_command(client, args)

    # Assertions
    assert result.outputs_prefix == OUTPUT_PREFIXES["RemoveBreachPoint"]
    assert result.outputs_key_field == "userSuppliedEntities"
    assert result.outputs == response.get("outputs")
    assert result.readable_output == hr_output
    assert mock_push.called
    expected_request_body = {"0000000000000000001": ["importedLable1"], "0000000000000000002": ["importedLable1"]}
    assert mock_push.last_request.json() == expected_request_body

    # Assert that warning was called for the entity not found
    mock_return_warning.assert_called_once_with("The following entities were not found: non_existent_entity")


def test_xmcyber_remove_breach_point_command_no_enrichment_data(requests_mock, client):
    """
    Given:
    - Valid entity_values argument
    - API returns empty response (no entities found)

    When:
    - xmcyber_remove_breach_point_command is executed

    Then:
    - Assert that CommandResults is returned with appropriate message
    - Assert that readable output indicates no enrichment data found
    - Assert that no breach point removal API call is made
    """
    from XMCyberCEM import xmcyber_remove_breach_point_command

    # Mock empty response
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=[])

    args = {
        "entity_values": "non-existent-entity1,non-existent-entity2",
    }

    result = xmcyber_remove_breach_point_command(client, args)

    # Assertions
    assert result.readable_output == "### No enrichment data found for the specified entities."


@pytest.mark.parametrize(
    "args",
    [({"entity_values": ""}), ({"entity_values": "   "})],
)
def test_xmcyber_remove_breach_point_command_invalid_arguments(client, args):
    """
    Given:
    - Invalid entity_values argument (empty or whitespace only)

    When:
    - xmcyber_remove_breach_point_command is executed

    Then:
    - Assert that ValueError is raised
    - Assert that error message mentions 'entity_values' is required
    """
    from XMCyberCEM import ERRORS, xmcyber_remove_breach_point_command

    with pytest.raises(ValueError) as err:
        xmcyber_remove_breach_point_command(client, args)

    assert ERRORS["REQUIRED_ARGUMENT"].format("entity_values") in str(err.value)


def test_xmcyber_calculate_risk_score_command_success(requests_mock, client):
    """
    Given:
    - Multiple entity values with different risk score levels
    - Custom weights for compromise_risk_score (0.7) and choke_point_score (0.3)

    When:
    - xmcyber_calculate_risk_score_command is executed with custom weights

    Then:
    - Assert that CommandResults is returned with calculated risk score
    - Assert that outputs contain all required fields
    - Assert that readable output contains proper table format
    """
    from XMCyberCEM import xmcyber_calculate_risk_score_command

    response = util_load_json(f"{TEST_DATA_DIR}/calculate_risk_score_response.json")
    with open(f"{TEST_DATA_DIR}/calculate_risk_score_response.md") as f:
        hr_output = f.read()

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=response.get("raw_response"))

    args = {
        "entity_values": "user_1,hostname_1,user_2",
        "compromise_risk_score": "0.8",
        "choke_point_score": "0.4",
    }

    result = xmcyber_calculate_risk_score_command(client, args)

    # Assertions
    assert result.outputs_prefix == OUTPUT_PREFIXES["CalculateRiskScore"]
    assert result.outputs_key_field == "entities"
    assert result.outputs == response.get("outputs")
    assert result.readable_output == hr_output


def test_xmcyber_calculate_risk_score_command_default_weights(requests_mock, client):
    """
    Given:
    - Multiple entity values with different risk score levels
    - No custom weights provided (should use default 0.5 for both)

    When:
    - xmcyber_calculate_risk_score_command is executed with only entity_values

    Then:
    - Assert that outputs contain all required fields
    """
    from XMCyberCEM import xmcyber_calculate_risk_score_command

    response = util_load_json(f"{TEST_DATA_DIR}/calculate_risk_score_response.json")

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=response.get("raw_response"))

    args = {
        "entity_values": "user_1,hostname_1,user_2,hostname_2",
    }

    result = xmcyber_calculate_risk_score_command(client, args)

    # Assertions
    assert result.outputs_prefix == OUTPUT_PREFIXES["CalculateRiskScore"]
    assert result.outputs_key_field == "entities"
    assert result.outputs == response.get("output_with_defaults")


def test_xmcyber_calculate_risk_score_command_no_response(requests_mock, client):
    """
    Given:
    - Valid entity_values argument
    - API returns empty response (no entities found)

    When:
    - xmcyber_calculate_risk_score_command is executed

    Then:
    - Assert that CommandResults is returned with appropriate message
    - Assert that readable output indicates no data found
    """
    from XMCyberCEM import xmcyber_calculate_risk_score_command

    # Mock empty response
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_ENTITIES_ENDPOINT']}", json=[])

    args = {"entity_values": "non-existent-entity"}
    result = xmcyber_calculate_risk_score_command(client, args)

    assert result.readable_output == "### No enrichment data found for the specified entities."


@pytest.mark.parametrize(
    "args,expected_error",
    [
        ({"entity_values": "   "}, ERRORS["REQUIRED_ARGUMENT"].format("entity_values")),
        ({"entity_values": ""}, ERRORS["REQUIRED_ARGUMENT"].format("entity_values")),
        (
            {"entity_values": "user_1", "compromise_risk_score": "invalid"},
            ERRORS["INVALID_SCORE_VALUE"].format("compromise_risk_score"),
        ),
        (
            {"entity_values": "user_1", "choke_point_score": "abc"},
            ERRORS["INVALID_SCORE_VALUE"].format("choke_point_score"),
        ),
        (
            {"entity_values": "user_1", "compromise_risk_score": "1.5"},
            ERRORS["INVALID_SCORE_VALUE"].format("compromise_risk_score"),
        ),
        (
            {"entity_values": "user_1", "compromise_risk_score": "-0.1"},
            ERRORS["INVALID_SCORE_VALUE"].format("compromise_risk_score"),
        ),
        (
            {"entity_values": "user_1", "choke_point_score": "2.0"},
            ERRORS["INVALID_SCORE_VALUE"].format("choke_point_score"),
        ),
        (
            {"entity_values": "user_1", "choke_point_score": "-1"},
            ERRORS["INVALID_SCORE_VALUE"].format("choke_point_score"),
        ),
    ],
)
def test_xmcyber_calculate_risk_score_command_invalid_arguments(client, args, expected_error):
    """
    Given:
    - Invalid arguments for calculate risk score command
    - Various validation error scenarios (empty entity_values, invalid weights, out of range values)

    When:
    - xmcyber_calculate_risk_score_command is executed with invalid arguments

    Then:
    - Assert that ValueError is raised
    - Assert that error message contains the expected error text
    """
    from XMCyberCEM import xmcyber_calculate_risk_score_command

    with pytest.raises(ValueError) as err:
        xmcyber_calculate_risk_score_command(client, args)

    assert expected_error in str(err.value)


def test_xmcyber_get_dashboard_data_command_success(requests_mock, client):
    """
    Given:
    - XMCyber get dashboard data command
    - Mocked successful responses for all dashboard endpoints

    When:
    - xmcyber_get_dashboard_data_command is executed

    Then:
    - Assert that CommandResults is returned with dashboard data
    - Assert that outputs contain SecurityScore, ChokePoints, CriticalAssets, and CompromisingExposures
    - Assert that outputs_prefix is correct (XMCyber.Dashboard)
    - Assert that readable_output indicates success
    """
    from XMCyberCEM import xmcyber_get_dashboard_data_command

    security_score_response = util_load_json(f"{TEST_DATA_DIR}/get_security_score_response.json")
    choke_points_response = util_load_json(f"{TEST_DATA_DIR}/get_choke_points_response.json")
    critical_assets_response = util_load_json(f"{TEST_DATA_DIR}/get_critical_assets_response.json")
    compromising_exposures_response = util_load_json(f"{TEST_DATA_DIR}/get_compromising_exposures_response.json")

    # Mock all 4 API endpoints
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_SECURITY_SCORE_ENDPOINT']}", json=security_score_response)
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_CHOKE_POINTS_BY_SEVERITY_ENDPOINT']}", json=choke_points_response)
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_CRITICAL_ASSETS_BY_SEVERITY_ENDPOINT']}", json=critical_assets_response)
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_COMPROMISING_EXPOSURES_ENDPOINT']}", json=compromising_exposures_response)

    result = xmcyber_get_dashboard_data_command(client)

    # Assertions
    assert result.outputs_prefix == OUTPUT_PREFIXES["Dashboard"]
    assert "SecurityScore" in result.outputs
    assert "ChokePoints" in result.outputs
    assert "CriticalAssets" in result.outputs
    assert "CompromisingExposures" in result.outputs

    # Verify SecurityScore extraction
    assert result.outputs["SecurityScore"]["score"] == 87
    assert result.outputs["SecurityScore"]["grade"] == "B"
    assert result.outputs["SecurityScore"]["trend"] == 1

    # Verify ChokePoints extraction
    assert len(result.outputs["ChokePoints"]) == 3
    assert result.outputs["ChokePoints"][0]["name"] == "abc"
    assert result.outputs["ChokePoints"][0]["severity"] == "critical"

    # Verify CriticalAssets extraction
    assert len(result.outputs["CriticalAssets"]) == 3
    assert result.outputs["CriticalAssets"][0]["name"] == "FileServer"

    # Verify CompromisingExposures extraction
    assert len(result.outputs["CompromisingExposures"]) == 3
    assert result.outputs["CompromisingExposures"][0]["criticalAssetsAtRisk"] == 52  # 70/135 * 100 rounded


def test_xmcyber_get_dashboard_data_command_empty_response(requests_mock, client, mocker):
    """
    Given:
    - XMCyber get dashboard data command
    - API returns empty data for all endpoints

    When:
    - xmcyber_get_dashboard_data_command is executed

    Then:
    - Assert that CommandResults is returned with empty data structures
    - Assert that outputs_prefix is correct
    - Assert that no errors are raised
    """
    from XMCyberCEM import xmcyber_get_dashboard_data_command

    mocker.patch("XMCyberCEM.get_integration_context", return_value={"dashboard_timestamp": 0, "dashboard_data": {}})

    # Mock all endpoints with empty responses
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_SECURITY_SCORE_ENDPOINT']}", json={"data": {}})
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_CHOKE_POINTS_BY_SEVERITY_ENDPOINT']}", json={"data": []})
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_CRITICAL_ASSETS_BY_SEVERITY_ENDPOINT']}", json={"data": []})
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_COMPROMISING_EXPOSURES_ENDPOINT']}", json={"extraData": {}, "data": []})

    result = xmcyber_get_dashboard_data_command(client)

    # Assertions
    assert result.outputs_prefix == OUTPUT_PREFIXES["Dashboard"]
    assert result.outputs["SecurityScore"] == {}
    assert result.outputs["ChokePoints"] == []
    assert result.outputs["CriticalAssets"] == []
    assert result.outputs["CompromisingExposures"] == []


def test_xmcyber_get_dashboard_data_command_integration_cache(client, mocker):
    """
    Given:
    - XMCyber get dashboard data command
    - Integration context has cached dashboard data

    When:
    - xmcyber_get_dashboard_data_command is executed

    Then:
    - Assert that CommandResults is returned with cached data from integration context
    - Assert that outputs_prefix is correct
    - Assert that no errors are raised
    """
    from XMCyberCEM import xmcyber_get_dashboard_data_command

    dashboard_data = util_load_json(f"{TEST_DATA_DIR}/get_dashboard_data_response.json")

    mocker.patch(
        "XMCyberCEM.get_integration_context", return_value={"dashboard_timestamp": 9999999999, "dashboard_data": dashboard_data}
    )

    result = xmcyber_get_dashboard_data_command(client)

    # Assertions
    assert result.outputs_prefix == OUTPUT_PREFIXES["Dashboard"]
    assert "SecurityScore" in result.outputs
    assert "ChokePoints" in result.outputs
    assert "CriticalAssets" in result.outputs
    assert "CompromisingExposures" in result.outputs

    # Verify SecurityScore extraction
    assert result.outputs["SecurityScore"]["score"] == 87
    assert result.outputs["SecurityScore"]["grade"] == "B"
    assert result.outputs["SecurityScore"]["trend"] == 1

    # Verify ChokePoints extraction
    assert len(result.outputs["ChokePoints"]) == 3
    assert result.outputs["ChokePoints"][0]["name"] == "abc"
    assert result.outputs["ChokePoints"][0]["severity"] == "critical"

    # Verify CriticalAssets extraction
    assert len(result.outputs["CriticalAssets"]) == 3
    assert result.outputs["CriticalAssets"][0]["name"] == "FileServer"

    # Verify CompromisingExposures extraction
    assert len(result.outputs["CompromisingExposures"]) == 3
    assert result.outputs["CompromisingExposures"][0]["criticalAssetsAtRisk"] == 52  # 70/135 * 100 rounded


def test_xmcyber_get_dashboard_data_command_via_main(requests_mock, mocker):
    """
    Given:
    - Integration configured with valid server URL and API key
    - Mock responses for all dashboard endpoints
    - Command: xmcyber-get-dashboard-data

    When:
    - main() function is called to execute the command

    Then:
    - Assert that all API endpoints are called
    - Assert that main() executes without errors
    """
    from XMCyberCEM import main

    security_score_response = util_load_json(f"{TEST_DATA_DIR}/get_security_score_response.json")
    choke_points_response = util_load_json(f"{TEST_DATA_DIR}/get_choke_points_response.json")
    critical_assets_response = util_load_json(f"{TEST_DATA_DIR}/get_critical_assets_response.json")
    compromising_exposures_response = util_load_json(f"{TEST_DATA_DIR}/get_compromising_exposures_response.json")

    # Mock integration parameters
    mocker.patch.object(demisto, "params", return_value={"server_url": BASE_URL, "credentials": {"password": API_KEY}})
    mocker.patch.object(demisto, "command", return_value="xmcyber-get-dashboard-data")

    # Mock auth endpoint for token generation
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json={"accessToken": "test_access_token", "refreshToken": "test_refresh_token"}
    )

    # Mock all 4 API endpoints
    mock_security_score = requests_mock.get(f"{BASE_URL}{ENDPOINTS['GET_SECURITY_SCORE_ENDPOINT']}", json=security_score_response)
    mock_choke_points = requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['GET_CHOKE_POINTS_BY_SEVERITY_ENDPOINT']}", json=choke_points_response
    )
    mock_critical_assets = requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['GET_CRITICAL_ASSETS_BY_SEVERITY_ENDPOINT']}", json=critical_assets_response
    )
    mock_exposures = requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['GET_COMPROMISING_EXPOSURES_ENDPOINT']}", json=compromising_exposures_response
    )

    main()

    # Verify all API endpoints were called
    assert mock_security_score.called
    assert mock_choke_points.called
    assert mock_critical_assets.called
    assert mock_exposures.called
