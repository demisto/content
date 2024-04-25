import json
from freezegun import freeze_time

MOCK_BASEURL = "https://test.com"
MOCK_CLIENT_ID = "example_client_id"
MOCK_CLIENT_PASSWORD = "example_password"
MOCK_USERNAME = "example_username"


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


"""*****TEST LOGIN****"""


def test_login_first_time_token_creation(mocker):
    """
    Given: An empty integration context
    When: Login is called for the first time
    Then: Create a new token and save it to the integration context
    """
    from VenafiV2 import Client

    mocker.patch("VenafiV2.get_integration_context", return_value={})
    mocker.patch.object(Client, '_http_request', return_value={
        "access_token": "access_token",
        "refresh_token": "refresh_token",
        "expires_in": 7775999,
        "expires": 1721806543,
        "token_type": "Bearer",
        "scope": "certificate",
        "identity": "local:{identity}",
        "refresh_until": 1745566543
    })

    client = Client(
        base_url=MOCK_BASEURL,
        verify=True,
        username=MOCK_USERNAME,
        password=MOCK_CLIENT_PASSWORD,
        client_id=MOCK_CLIENT_ID,
        proxy=False
    )

    assert client.token == "access_token"


@freeze_time("2024-04-25 00:00:00")
def test_login_with_valid_token(mocker):
    """
    Given: A token in the integration context with a valid expiration time
    When: Login is called with a valid token
    Then: Fetch the token from the integration context and log in
    """
    from VenafiV2 import Client

    mocker.patch("VenafiV2.get_integration_context", return_value={
        "token": "access_token",
        "expires": "1715032135"
    })

    client = Client(
        base_url=MOCK_BASEURL,
        verify=True,
        username=MOCK_USERNAME,
        password=MOCK_CLIENT_PASSWORD,
        client_id=MOCK_CLIENT_ID,
        proxy=False
    )

    assert client.token == "access_token"


@freeze_time("2024-04-25 00:00:00")
def test_login_with_invalid_token_refresh_required(mocker):
    """
    Given: A token in the integration context with an expired expiration time
    When: Login is called with an invalid token
    Then: Request a refresh token and save it to the integration context
    """
    from VenafiV2 import Client

    mocker.patch("VenafiV2.get_integration_context", return_value={
        "token": "access_token",
        "expires": "1615032135",
        "refresh_token": "refresh_token"
    })

    mocker.patch.object(Client, '_http_request', return_value={
        "access_token": "access_token",
        "refresh_token": "refresh_token",
        "expires_in": 7775999,
        "expires": 1721806543,
        "token_type": "Bearer",
        "scope": "certificate",
        "identity": "local:{identity}",
        "refresh_until": 1745566543
    })

    client = Client(
        base_url=MOCK_BASEURL,
        verify=True,
        username=MOCK_USERNAME,
        password=MOCK_CLIENT_PASSWORD,
        client_id=MOCK_CLIENT_ID,
        proxy=False
    )

    assert client.token == "access_token"


"""*****COMMAND FUNCTIONS****"""


def test_get_certificates_command(mocker):
    """
    Given: Client details
    When: The "Get certificates" command is called
    Then: Retrieve the user's certificates
    """
    from VenafiV2 import Client
    from VenafiV2 import get_certificates_command
    mocker.patch.object(Client, '_login', return_value="access_token")

    client = Client(
        base_url=MOCK_BASEURL,
        verify=True,
        username=MOCK_USERNAME,
        password=MOCK_CLIENT_PASSWORD,
        client_id=MOCK_CLIENT_ID,
        proxy=False
    )

    raw_response = util_load_json("test_data/raw_certificates.json")
    mocker.patch.object(Client, '_http_request', return_value=raw_response)

    command_result = get_certificates_command(client, {})
    outputs = command_result.outputs
    certificates = outputs.get('Certificates', [])
    assert len(certificates) == 2
    assert certificates == raw_response.get('Certificates', [])
    assert certificates[0].get('Guid') == "{first_guid}"
    assert certificates[1].get('Guid') == "{second_guid}"
    assert certificates[0].get('_links') is None


def test_get_certificate_details_command(mocker):
    """
    Given: Client details
    When: The "Get certificate details" command is called
    Then: Retrieve details of a specific certificate
    """
    from VenafiV2 import Client
    from VenafiV2 import get_certificate_details_command
    mocker.patch.object(Client, '_login', return_value="access_token")

    client = Client(
        base_url=MOCK_BASEURL,
        verify=True,
        username=MOCK_USERNAME,
        password=MOCK_CLIENT_PASSWORD,
        client_id=MOCK_CLIENT_ID,
        proxy=False
    )

    raw_response = util_load_json("test_data/raw_certificate_details.json")
    mocker.patch.object(Client, '_http_request', return_value=raw_response)
    command_result = get_certificate_details_command(client, {})
    certificate_details = command_result.outputs

    assert certificate_details == raw_response
    assert certificate_details.get('Guid') == '{certificate_details_guid}'
    assert certificate_details.get('Name') == 'test.certificates.com'

    verbose_certificate_details = certificate_details.get('CertificateDetails')
    assert verbose_certificate_details is not None
    assert verbose_certificate_details.get('KeyAlgorithm') == 'RSA'
    assert verbose_certificate_details.get('AIACAIssuerURL', [])[0] == 'https://test.certificates.com'
