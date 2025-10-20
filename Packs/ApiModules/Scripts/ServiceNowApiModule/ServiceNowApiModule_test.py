import pytest

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


@pytest.mark.parametrize("label", ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"])
def test_valid_private_key_formatting(label):
    """
    Given:
    - A private key string with correct BEGIN/END labels and valid base64 content
    - The key has inconsistent newlines or extra whitespace

    When:
    - Calling ServiceNowClient._validate_and_format_private_key

    Then:
    - The key is cleaned and formatted to PEM standard
    - Base64 content is wrapped at 64 characters
    - BEGIN/END labels are preserved
    """
    key_data = "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAlS3dJdfO8Xf\nj57s\n=="
    raw_key = f"""-----BEGIN {label}-----

    {key_data}

    -----END {label}-----
    """
    result = ServiceNowClient._validate_and_format_private_key(raw_key)

    expected_lines = key_data.replace("\n", "").replace(" ", "")
    expected_lines = [expected_lines[i : i + 64] for i in range(0, len(expected_lines), 64)]
    expected_key = f"-----BEGIN {label}-----\n" + "\n".join(expected_lines) + f"\n-----END {label}-----"

    assert result == expected_key


def test_invalid_private_key_raises():
    """
    Given:
    - A string that is not a valid private key (missing proper PEM headers)

    When:
    - Calling ServiceNowClient._validate_and_format_private_key

    Then:
    - A ValueError is raised indicating invalid format
    """
    invalid_key = "this is not a private key"

    with pytest.raises(ValueError, match="Invalid private key format."):
        ServiceNowClient._validate_and_format_private_key(invalid_key)


def test_private_key_with_extra_characters_is_cleaned():
    """
    Given:
    - A private key string with tabs, spaces, and newline characters in the base64 content

    When:
    - Calling ServiceNowClient._validate_and_format_private_key

    Then:
    - All non-base64 characters are removed
    - The cleaned content is returned in 64-character lines
    - PEM format is preserved
    """
    label = "RSA PRIVATE KEY"
    key_data = "MIIB\tVgI BADA\nNBgkqhkiG9w0BAQ EFAASCAT8wggE7AgEAAkEA\nlS3dJd=="

    raw_key = f"""-----BEGIN {label}-----
    {key_data}
    -----END {label}-----"""

    result = ServiceNowClient._validate_and_format_private_key(raw_key)

    clean_base64 = re.sub(r"[^A-Za-z0-9+/=]", "", key_data)
    expected_lines = [clean_base64[i : i + 64] for i in range(0, len(clean_base64), 64)]
    expected_key = f"-----BEGIN {label}-----\n" + "\n".join(expected_lines) + f"\n-----END {label}-----"

    assert result == expected_key


def test_private_key_preserves_label():
    """
    Given:
    - A valid EC PRIVATE KEY with properly labeled BEGIN/END headers
    - Base64 content longer than 64 characters

    When:
    - Calling ServiceNowClient._validate_and_format_private_key

    Then:
    - The returned PEM keeps the original label in both headers
    - Base64 content is correctly wrapped at 64-character lines
    """
    label = "EC PRIVATE KEY"
    content = "A" * 70  # arbitrary base64 content
    raw_key = f"-----BEGIN {label}-----\n{content}\n-----END {label}-----"

    result = ServiceNowClient._validate_and_format_private_key(raw_key)

    expected_lines = [content[i : i + 64] for i in range(0, len(content), 64)]
    expected_key = f"-----BEGIN {label}-----\n" + "\n".join(expected_lines) + f"\n-----END {label}-----"

    assert result == expected_key


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
