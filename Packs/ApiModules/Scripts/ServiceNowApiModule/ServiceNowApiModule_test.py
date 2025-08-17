import demistomock as demisto
from Packs.ServiceNow.Integrations.ServiceNowv2.test_data.response_constants import JWT_PARAMS
from ServiceNowApiModule import *

PARAMS = {
    "insecure": False,
    "credentials": {"identifier": "user1", "password": "12345"},
    "proxy": False,
    "client_id": "client_id",
    "client_secret": "client_secret",
    "use_oauth": True,
}


# Unit tests for OAuth authorization
def test_get_access_token(mocker):
    """Unit test
    Given
    A client using OAuth authorization
    - (a) Integration context with a valid access token.
    - (b) Integration context with an expired access token.
    - (c) Empty integration context (mocks the case that the user didn't run the login command first).
    When
    - Calling the get_access_token function while using OAuth 2.0 authorization.
    Then
    - (a) Validate that the previous access token is returned, since it is still valid.
    - (b) Validate that a new access token is returned, as the previous one expired.
    - (c) Validate that an error is raised, asking the user to first run the login command.
    """
    valid_access_token = {"access_token": "previous_token", "refresh_token": "refresh_token", "expiry_time": 1}
    expired_access_token = {"access_token": "previous_token", "refresh_token": "refresh_token", "expiry_time": -1}

    from requests.models import Response

    new_token_response = Response()
    new_token_response._content = b'{"access_token": "new_token", "refresh_token": "refresh_token", "expires_in": 1}'
    new_token_response.status_code = 200

    mocker.patch("ServiceNowApiModule.date_to_timestamp", return_value=0)
    client = ServiceNowClient(
        credentials=PARAMS.get("credentials", {}),
        use_oauth=True,
        client_id=PARAMS.get("client_id", ""),
        client_secret=PARAMS.get("client_secret", ""),
        url=PARAMS.get("url", ""),
        verify=PARAMS.get("insecure", False),
        proxy=PARAMS.get("proxy", False),
        headers=PARAMS.get("headers", ""),
    )

    # Validate the previous access token is returned, as it is still valid
    mocker.patch.object(demisto, "getIntegrationContext", return_value=valid_access_token)
    assert client.get_access_token() == "previous_token"

    # Validate that a new access token is returned when the previous has expired
    mocker.patch.object(demisto, "getIntegrationContext", return_value=expired_access_token)
    mocker.patch.object(BaseClient, "_http_request", return_value=new_token_response)
    assert client.get_access_token() == "new_token"

    # Validate that an error is returned in case the user didn't run the login command first
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    try:
        client.get_access_token()
    except Exception as e:
        assert "Could not create an access token" in e.args[0]


def test_separate_client_id_and_refresh_token():
    """Unit test
    Given
    - Integration parameters and a client_id parameter which contains a '@' characters that separates between the 'real'
      client id and the refresh token.
    When
    - Calling the ServiceNowClient constructor while using OAuth 2.0 authorization.
    Then
    - Verify that the client_id field of the client contains only the 'real' client id.
    """
    client_id_with_strudel = "client_id@refresh_token"
    client = ServiceNowClient(
        credentials=PARAMS.get("credentials", {}),
        use_oauth=True,
        client_id=client_id_with_strudel,
        client_secret=PARAMS.get("client_secret", ""),
        url=PARAMS.get("url", ""),
        verify=PARAMS.get("insecure", False),
        proxy=PARAMS.get("proxy", False),
        headers=PARAMS.get("headers", ""),
    )
    assert client.client_id == "client_id"


def test_validate_and_format_private_key_valid():
    valid_key = "-----BEGIN PRIVATE KEY-----" "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" "-----END PRIVATE KEY-----"
    result = ServiceNowClient._validate_and_format_private_key(valid_key)
    assert result.startswith("-----BEGIN PRIVATE KEY-----")
    assert result.endswith("-----END PRIVATE KEY-----")
    assert " " not in result  # spaces replaced


def test_validate_and_format_private_key_invalid():
    invalid_key = "INVALID KEY CONTENT"
    try:
        ServiceNowClient._validate_and_format_private_key(invalid_key)
    except ValueError as e:
        assert "Invalid private key format" in str(e)
    else:
        assert False, "ValueError not raised for invalid key"


def test_validate_and_format_private_key_spaces():
    key_with_spaces = "-----BEGIN PRIVATE KEY----- MIIE vQIBADAN Bgkqh kiG9w0 BAEF AASC -----END PRIVATE KEY-----"
    result = ServiceNowClient._validate_and_format_private_key(key_with_spaces)
    assert " " not in result
    assert result.count("\n") > 2


def test_validate_and_format_private_key_double_newlines():
    key_with_double_newlines = "-----BEGIN PRIVATE KEY-----\n\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n\n-----END PRIVATE KEY-----"
    result = ServiceNowClient._validate_and_format_private_key(key_with_double_newlines)
    assert "\n\n" not in result


def test_servicenow_client_jwt_init(mocker):
    """
    Given:
    - JWT credentials (jwt_params)
    When:
    - Initializing ServiceNowClient with jwt_params
    Then:
    - JWT is created and assigned to self.jwt
    - No exceptions are raised
    """
    mocker.patch("jwt.encode", return_value="jwt_token_stub")
    client = ServiceNowClient(
        credentials=PARAMS["credentials"],
        use_oauth=True,
        client_id=PARAMS["client_id"],
        client_secret=PARAMS["client_secret"],
        url="https://example.com",
        verify=PARAMS["insecure"],
        proxy=PARAMS["proxy"],
        headers=None,
        jwt_params=JWT_PARAMS,
    )
    assert hasattr(client, "jwt")
    assert client.jwt == "jwt_token_stub"


def test_servicenow_client_jwt_none():
    """
    Given:
    - No jwt_params provided
    When:
    - Initializing ServiceNowClient
    Then:
    - The client should not have a 'jwt' attribute
    """
    client = ServiceNowClient(
        credentials=PARAMS["credentials"],
        use_oauth=True,
        client_id=PARAMS["client_id"],
        client_secret=PARAMS["client_secret"],
        url="https://example.com",
        verify=PARAMS["insecure"],
        proxy=PARAMS["proxy"],
        headers=None,
        jwt_params=None,
    )
    assert not hasattr(client, "jwt") or client.jwt is None
