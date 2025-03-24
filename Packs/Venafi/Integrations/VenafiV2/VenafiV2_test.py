import json
import pytest
from freezegun import freeze_time
from VenafiV2 import Client

MOCK_BASEURL = "https://mock.api.url.com"
MOCK_CLIENT_ID = "mock_client_id"
MOCK_CLIENT_PASSWORD = "mock_password"
MOCK_USERNAME = "mock_username"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture(autouse=True)
@freeze_time("2024-04-25 00:00:00")
def mock_client_with_valid_token(mocker) -> Client:
    """
    Establish a connection to the client with a URL and user credentials.
    This client contains a valid token.

    Returns:
        Client: Connection to client.
    """

    mocker.patch("VenafiV2.get_integration_context", return_value={"token": "access_token", "expires": "1715032135"})

    return Client(
        base_url=MOCK_BASEURL,
        verify=False,
        username=MOCK_USERNAME,
        password=MOCK_CLIENT_PASSWORD,
        client_id=MOCK_CLIENT_ID,
        proxy=False,
    )


"""*****TEST LOGIN****"""


def test_login_first_time_token_creation(mocker):
    """
    Given: An empty integration context
    When: Login is called for the first time
    Then: Create a new token and save it to the integration context
    """

    mock_response = util_load_json("test_data/mock_response_login_first_time_token_creation.json")
    mocker.patch.object(Client, "_http_request", return_value=mock_response)
    mocker.patch("VenafiV2.get_integration_context", return_value={})

    client = Client(
        base_url=MOCK_BASEURL,
        verify=False,
        username=MOCK_USERNAME,
        password=MOCK_CLIENT_PASSWORD,
        client_id=MOCK_CLIENT_ID,
        proxy=False,
    )

    assert client.token == "access_token"


@freeze_time("2024-04-25 00:00:00")
def test_login_with_valid_token(mock_client_with_valid_token):
    """
    Given: A token in the integration context with a valid expiration time
    When: Login is called with a valid token
    Then: Fetch the token from the integration context and log in
    """

    assert mock_client_with_valid_token.token == "access_token"


@freeze_time("2024-04-25 00:00:00")
def test_login_with_invalid_token_refresh_required(mocker):
    """
    Given: A token in the integration context with an expired expiration time
    When: Login is called with an invalid token
    Then: Request a refresh token and save it to the integration context
    """

    mocker.patch(
        "VenafiV2.get_integration_context",
        return_value={"token": "access_token", "expires": "1615032135", "refresh_token": "refresh_token"},
    )

    mock_response = util_load_json("test_data/mock_response_login_without_valid_token.json")
    mocker.patch.object(Client, "_http_request", return_value=mock_response)

    client = Client(
        base_url=MOCK_BASEURL,
        verify=False,
        username=MOCK_USERNAME,
        password=MOCK_CLIENT_PASSWORD,
        client_id=MOCK_CLIENT_ID,
        proxy=False,
    )

    assert client.token == "access_token"


@freeze_time("2024-04-25 00:00:00")
def test_get_certificates_command(mocker, mock_client_with_valid_token):
    """
    Given: Client details
    When: The "Get certificates" command is called
    Then: Retrieve the user's certificates
    """

    from VenafiV2 import get_certificates_command

    raw_response = util_load_json("test_data/raw_certificates.json")
    mocker.patch.object(Client, "_http_request", return_value=raw_response)
    command_result = get_certificates_command(mock_client_with_valid_token, {})
    certificates = command_result.outputs

    assert len(certificates) == 2
    assert certificates == raw_response.get("Certificates", [])
    assert certificates[0].get("ID") == "first_guid"
    assert certificates[1].get("ID") == "second_guid"
    assert certificates[0].get("Guid") is None
    assert certificates[1].get("Guid") is None
    assert certificates[0].get("_links") is None


@freeze_time("2024-04-25 00:00:00")
def test_get_certificate_details_command(mocker, mock_client_with_valid_token):
    """
    Given: Client details
    When: The "Get certificate details" command is called
    Then: Retrieve details of a specific certificate
    """

    from VenafiV2 import get_certificate_details_command

    raw_response = util_load_json("test_data/raw_certificate_details.json")
    mocker.patch.object(Client, "_http_request", return_value=raw_response)
    command_result = get_certificate_details_command(mock_client_with_valid_token, {"guid": "guid"})
    certificate_details = command_result.outputs

    assert certificate_details == raw_response
    assert certificate_details.get("ID") == "certificate_details_guid"
    assert certificate_details.get("Guid") is None
    assert certificate_details.get("Name") == "test.certificates.com"

    verbose_certificate_details = certificate_details.get("CertificateDetails")
    assert verbose_certificate_details is not None
    assert verbose_certificate_details.get("KeyAlgorithm") == "RSA"
    assert verbose_certificate_details.get("AIACAIssuerURL", [])[0] == "https://test.certificates.com"
