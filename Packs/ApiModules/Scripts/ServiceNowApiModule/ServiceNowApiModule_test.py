import demistomock as demisto
from Packs.ServiceNow.Integrations.ServiceNowv2.test_data.response_constants import JWT_PARAMS
from ServiceNowApiModule import *

PARAMS = {
    "insecure": False,
    "credentials": {"identifier": "user1", "password:": "12345"},
    "proxy": False,
    "client_id": "client_id",
    "client_secret": "client_secret",
    "use_oauth": True,
}


def test_invalid_private_key():
    """
    Given:
    - Invalid format of private key
    When:
    - creating the JWT
    Then:
    - Raise a Value error with informative message
    """
    params = {"private_key": "-----INVALID FORMAT----- test_token -----INVALID FORMAT-----", "kid": "test1", "sub": "test"}

    with pytest.raises(ValueError) as e:
        Client(
            "server_url",
            "sc_server_url",
            "cr_server_url",
            "username",
            "password",
            "verify",
            "fetch_time",
            "sysparm_query",
            sysparm_limit=10,
            timestamp_field="opened_at",
            ticket_type="incident",
            get_attachments=False,
            incident_name="description",
            oauth_params=OAUTH_PARAMS,
            jwt_params=params,
        )
    assert "Invalid private key format" in str(e)


def test_jwt_checker(mocker):
    """
    Given:
    - private key
    When:
    - creating a jwt
    Then:
    - (a) that the return type is a string
    - (b) validate the pem format
    """

    mocker.patch.object(jwt, "encode", return_value="")
    client = Client(
        "server_url",
        "sc_server_url",
        "cr_server_url",
        "username",
        "password",
        "verify",
        "fetch_time",
        "sysparm_query",
        sysparm_limit=10,
        timestamp_field="opened_at",
        ticket_type="incident",
        get_attachments=False,
        incident_name="description",
        oauth_params=OAUTH_PARAMS,
        jwt_params=JWT_PARAMS,
    )
    test_token = client.check_private_key(JWT_PARAMS["private_key"])
    assert isinstance(test_token, str)
    assert test_token.startswith("-----BEGIN PRIVATE KEY-----")
    assert test_token.endswith("-----END PRIVATE KEY-----")


def test_jwt_init(mocker):
    """
    Given:
    - JWT credential
    When:
    - User connect using JWT authentication
    Then:
    - create jwt
    """
    mocker.patch("jwt.encode", return_value="test")
    client = Client(
        "server_url",
        "sc_server_url",
        "cr_server_url",
        "username",
        "password",
        "verify",
        "fetch_time",
        "sysparm_query",
        sysparm_limit=10,
        timestamp_field="opened_at",
        ticket_type="incident",
        get_attachments=False,
        incident_name="description",
        oauth_params=OAUTH_PARAMS,
        jwt_params=JWT_PARAMS,
    )
    jwt = client.create_jwt()
    assert jwt == "test"


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
