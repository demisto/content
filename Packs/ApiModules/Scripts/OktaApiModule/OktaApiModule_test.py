import pytest
from freezegun import freeze_time

from pathlib import Path

from OktaApiModule import *


def load_test_data(folder: str, file_name: str) -> dict:
    """
    A function for loading and returning test data from files within the "test_data" folder.

    Args:
        folder (str): Name of the parent folder of the file within `test_data`.
        file_name (str): Name of a json file to load data from.

    Returns:
        dict: The data loaded from the file.
    """
    with open(Path("test_data") / folder / f"{file_name}.json") as f:
        return json.load(f)


def test_okta_client_required_params():
    """
    Given: An Okta Client is initialized with OAuth
    When: The required OAuth parameters are not provided.
    Then: Raise a ValueError.
    """
    with pytest.raises(ValueError) as e:
        OktaClient(
            base_url='https://test.url',
            api_token='X',
            auth_type=AuthType.OAUTH,
        )

    assert str(e.value) == 'Required OAuth parameters are missing: Client ID, Scopes, JWT algorithm, Private key'


def test_okta_client_no_required_params():
    """
    Given: An Okta Client is initialized without OAuth
    When: Only the required parameters are provided
    Then: Assure the client is initialized without an error.
    """
    OktaClient(
        base_url='https://test.url',
        api_token='X',
        auth_type=AuthType.API_TOKEN,
    )


def test_assign_app_role(mocker):
    """
    Given: An Okta Client is initialized with OAuth
    When: Assigning a role to a client application
    Then: Assure the call is made properly, and that the 'auth_type' parameter overrides the client's auth type.
    """
    client = OktaClient(
        base_url='https://test.url',
        api_token='X',
        auth_type=AuthType.OAUTH,
        client_id='X',
        scopes=['X'],
        private_key='X',
        jwt_algorithm=JWTAlgorithm.RS256
    )
    mocker.patch.object(client, 'get_token', return_value='JWT_TOKEN')
    http_request_mock = mocker.patch.object(client, 'http_request')
    client.assign_app_role(client_id='Y', role='X', auth_type=AuthType.API_TOKEN)

    assert http_request_mock.call_count == 1
    assert http_request_mock.call_args.kwargs == {
        'auth_type': AuthType.API_TOKEN,
        'url_suffix': '/oauth2/v1/clients/Y/roles',
        'method': 'POST',
        'json_data': {
            'type': 'X'
        }
    }


def test_initial_setup_role_already_assigned(mocker):
    """
    Given: An Okta Client is initialized with OAuth
    When: Running the initial setup, and the role assignment response says it's already assigned
    Then: Assure no error is raised.
    """
    mock_api_response_data = load_test_data('raw_api_responses', 'roles_already_assigned_error')
    mocker.patch.object(OktaClient, 'get_token')

    mock_response = requests.models.Response()
    mock_response.status_code = 409
    mock_response.headers = {'content-type': 'application/json'}
    mock_response._content = json.dumps(mock_api_response_data).encode('utf-8')

    mocker.patch.object(OktaClient, '_http_request', side_effect=DemistoException('Error in API call [409] - Conflict',
                                                                                  res=mock_response))

    OktaClient(  # 'initial_setup' is called within the constructor
        base_url='https://test.url',
        api_token='X',
        auth_type=AuthType.OAUTH,
        client_id='X',
        scopes=['X'],
        private_key='X',
        jwt_algorithm=JWTAlgorithm.RS256
    )


@freeze_time("2021-01-01 00:00:00")
def test_generate_jwt_token(mocker):
    """
    Given: An Okta Client is initialized with OAuth
    When: Generating a JWT token
    Then: Assure the token is generated correctly.
    """
    client = OktaClient(
        base_url='https://test.url',
        api_token='X',
        auth_type=AuthType.OAUTH,
        client_id='X',
        scopes=['X'],
        private_key='''-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDd5FcvCKgtXjkY
aiDdqpFAYKw6WxNEpZIGjzD9KhEqr7OZjpPoLeyGh1U6faAcN6XpkQugFA/2Gq+Z
j/pe1abiTCbctdE978FYVjXxbEEAtEn4x28s/bKah/xjjw+RjUyQB9DsioFkV1eN
9iJh5eOOIOjTDMBt7SxY1HivC0HjUKjCaMjdH2WxGu4na9phPOa7zixlgLqZGC8g
E1Ati5j3nOEOlmrNIf1Z/4zdJzEaMprBCymfEvrgMC7ibG9AokDcAj6Sl4xgvTRp
tTczCbUxF1jsnNNbuLyq/RuQ85SWB3mrRKT4OgPtz/ga3sm4l7Uq/YN71Gr/Lxaq
bkwWVMd/AgMBAAECggEBAKnMfacBYejtzJVRSXs3dlWkZMd3QGRsqzUXyG5DDcXz
lGVyxN6Mng5Ia8EJt0dAklcM5q+GCrzSqQPDON3vcviDO83z2H4kBXm65yarJ4cJ
b/3PZ9UvAsjcPRhWtpw0W51wTcFlMCT/7YE2FBOEX0E5D9HJVUwJjcEgPoX9AFuY
xYVpFvr1AoORde/RoJGoe+Z81hIRvcbrzfLHEMCB0pY0wxBuD5tyhEunIwLxG+6v
T1OHtuXDATEGabZQJKuhBfuP00YFRKxHIBLWPtkplQGFAXmBEeD5NIYfo+RBQFUH
GuvDTHoEvecn9ZHF4eOjJ88TXaGuXrFHwa0g0KMDNaECgYEA+ld2bkC4RXNWIzYI
4bOH7UBFrd74nz4zqNd2UZqP9R1al8nLgcESiT6izBbR+6wnNANIon5fXYGFK+wu
NGvKwuL1Xf04Ro/Z/i03QrV5fTgL/F8NX9F0kc6znxli9SrpswSjb1ZUoJmQXCew
ZYkCVavy3Zpgk8uHeeaHOOAI6k8CgYEA4uhC2Jy9Ysq6Eg79hVq0xHtXLl0VWfrU
5mugItrH90LmsCvKK4Qzg33BjhIMbE9vq63yFxW08845weuxUV6LalPSLOclE7D2
6exG5grcdGpqyWKc2qCAXP2uLys68cOfWduJoVUYsdAGbyNdvkI69VcTsI8pV6kR
bjzP+l50c9ECgYA3CVN4GbJpUln1k8OQGzAe8Kpg90whdkNVM0lH13seoD1ycWLU
O+YfVi3kQIAZnFdiD/bAAphkrjzg0yO1Up1ZCxx2dV0R5j4+qyIjAFKdPN0ltp/y
GNJP2+mRaLtguvZ17OchaxFf3WLnX7JgICbrPso9/dqNo4k9O3ku/9H18QKBgQDZ
LaMlfsgJ8a2ssSpYZBwW31LvbmqMR/dUX/jSw4KXmDICtrb3db50gX4rw/yeAl4I
/SF0lPMwU9eWU0fRcOORro7BKa+kLEH4XYzyi7y7tEtnW3p0CyExYCFCxmbRlgJE
WEtf3noXXtt5rmkAPJX/0wtmd3ADli+3yn7pzVQ6sQKBgQDJJITERtov019Cwuux
fCRUIbRyUH/PCN/VvsuKFs+BWbFTnqBXRDQetzTyuUvNKiL7GmWQuR/QpgYjLd9W
jxAayhtcVKeL96dqimK9twmw/NC5DveOVoReXx7io4gicmQi7AGq5WRkm8NUZRVE
1dH1Hhp7kjnPlUOUBvKf8mfFxQ==
-----END PRIVATE KEY-----''',
        jwt_algorithm=JWTAlgorithm.RS256
    )

    mocker.patch('uuid.uuid4', return_value="083f42d3-fab0-4af9-bebd-c9fa24fdc7c9")
    assert (client.generate_jwt_token("http://test.url")
            == ("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwOi8vdGVzdC51cmwiLCJpYXQiOjE2MDk0NTkyMDAsImV4cCI6MTYwOTQ2Mjg"
                "wMCwiaXNzIjoiWCIsInN1YiI6IlgiLCJqdGkiOiIwODNmNDJkMy1mYWIwLTRhZjktYmViZC1jOWZhMjRmZGM3YzkifQ.bBKg1iS_xz1MVyniW5CL"
                "XraIGipwKeyKD0g1Y3qUt0EFkXN_jmSHA6gDws1mBBF0OzAW96Yq9uLPpcRcXoz4K0RG29YdhS-QWZscqbhBUWmLneUvP3vvvKJuAEsjFICZjFC3"
                "bQzdOK09a5Jtv-QvzyWNeHv3jBcMYgydrDxnRIoLf2i0DcTzBOfnVOWt9karXjWWlkQPUtIUgMPFF6ZS1eXloWUvJYmiusd0HmpjWxHLPiT4f2dI"
                "KRJUVQLPu3_QHGapsEspvSziJ9EtKTfu77XBA8OvEAzySCIsalMSYNuCHAiuZzT7MxZy9fFWOWWr4k54FFJnWtJx4npTHcBBTw"))


def test_generate_oauth_token(mocker):
    """
    Given: An Okta Client is initialized with OAuth
    When: Generating an OAuth token
    Then: Assure the token generation API call is called correctly.
    """
    client = OktaClient(
        base_url='https://test.url',
        api_token='X',
        auth_type=AuthType.OAUTH,
        client_id='X',
        scopes=['X'],
        private_key='X',
        jwt_algorithm=JWTAlgorithm.RS256
    )

    mocker.patch.object(client, 'generate_jwt_token', return_value='JWT_TOKEN')
    http_request_mock = mocker.patch.object(client, 'http_request')
    client.generate_oauth_token(scopes=['X', 'Y'])

    assert http_request_mock.call_count == 1
    assert http_request_mock.call_args.kwargs == {
        'auth_type': AuthType.NO_AUTH,
        'full_url': 'https://test.url/oauth2/v1/token',
        'method': 'POST',
        'headers': {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        'data': {
            'grant_type': 'client_credentials',
            'scope': 'X Y',
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': 'JWT_TOKEN',
        }
    }


def test_get_token_create_new_token(mocker):
    """
    Given: An Okta Client is initialized with OAuth
    When: No existing token is available in the integration context
    Then: Assure a new token is generated, and that the integration context is updated with the new token.
    """
    import OktaApiModule
    client = OktaClient(  # 'initial_setup' is called within the constructor
        base_url='https://test.url',
        api_token='X',
        auth_type=AuthType.OAUTH,
        client_id='X',
        scopes=['X'],
        private_key='X',
        jwt_algorithm=JWTAlgorithm.RS256
    )

    mock_api_response_data = load_test_data('raw_api_responses', 'token_generation')
    mocker.patch.object(client, 'generate_oauth_token', return_value=mock_api_response_data)
    set_integration_context_spy = mocker.spy(OktaApiModule, 'set_integration_context')

    assert client.get_token() == 'XXX'
    assert set_integration_context_spy.call_count == 1
    integration_context_data = set_integration_context_spy.call_args.args[0]
    assert integration_context_data['token'] == 'XXX'
    assert integration_context_data['token_expiration']
    assert datetime.strptime(integration_context_data['token_expiration'], '%Y-%m-%dT%H:%M:%S')


@freeze_time("2021-01-01 00:00:00")
def test_get_token_use_existing(mocker):
    """
    Given: An Okta Client is initialized with OAuth
    When: An existing, valid token is available in the integration context
    Then: Assure the existing token is returned.
    """
    import OktaApiModule
    client = OktaClient(  # 'initial_setup' is called within the constructor
        base_url='https://test.url',
        api_token='X',
        auth_type=AuthType.OAUTH,
        client_id='X',
        scopes=['X'],
        private_key='X',
        jwt_algorithm=JWTAlgorithm.RS256
    )

    mocker.patch.object(OktaApiModule, 'get_integration_context', return_value={'token': 'X',
                                                                                'token_expiration': '2021-01-01T01:00:00'})
    assert client.get_token() == 'X'


@freeze_time("2021-01-01 01:00:00")
def test_get_token_regenerate_existing(mocker):
    """
    Given: An Okta Client is initialized with OAuth
    When: An existing, expired token is available in the integration context
    Then: Assure a new token is generated
    """
    import OktaApiModule
    client = OktaClient(  # 'initial_setup' is called within the constructor
        base_url='https://test.url',
        api_token='X',
        auth_type=AuthType.OAUTH,
        client_id='X',
        scopes=['X'],
        private_key='X',
        jwt_algorithm=JWTAlgorithm.RS256
    )

    mocker.patch.object(OktaApiModule, 'get_integration_context', return_value={'token': 'YYY',
                                                                                'token_expiration': '2021-01-01T01:00:00'})

    mock_api_response_data = load_test_data('raw_api_responses', 'token_generation')
    generate_oauth_token_mock = mocker.patch.object(client, 'generate_oauth_token', return_value=mock_api_response_data)

    assert client.get_token() == 'XXX'
    assert generate_oauth_token_mock.call_count == 1


def test_http_request_no_auth(mocker):
    """
    Given: An Okta Client is initialized with OAuth
    When: Making an API call with no authentication
    Then: Assure the call is made without any authentication headers.
    """
    client = OktaClient(
        base_url='https://test.url',
        api_token='X',
        auth_type=AuthType.API_TOKEN,
    )

    base_client_http_request_mock = mocker.patch.object(client, '_http_request')
    client.http_request(
        auth_type=AuthType.NO_AUTH,
        full_url='https://test.url',
        method='GET',
        headers={"test_header": "test_value"},
    )

    assert base_client_http_request_mock.call_count == 1
    assert base_client_http_request_mock.call_args.kwargs == {
        'full_url': 'https://test.url',
        'headers': {
            'test_header': 'test_value',
        },
        'method': 'GET',
    }


def test_http_request_api_token_auth(mocker):
    """
    Given: An Okta Client is initialized with OAuth
    When: Making an API call with API token authentication
    Then: Assure the call is made with the API token properly used in the 'Authorization' header.
    """
    client = OktaClient(
        base_url='https://test.url',
        api_token='X',
        auth_type=AuthType.API_TOKEN,
    )

    base_client_http_request_mock = mocker.patch.object(client, '_http_request')
    client.http_request(
        auth_type=AuthType.API_TOKEN,
        full_url='https://test.url',
        method='GET',
        headers={"test_header": "test_value"},
    )

    assert base_client_http_request_mock.call_count == 1
    assert base_client_http_request_mock.call_args.kwargs == {
        'full_url': 'https://test.url',
        'headers': {
            'Authorization': 'SSWS X',
            'test_header': 'test_value',
        },
        'method': 'GET',
    }


def test_http_request_oauth_auth(mocker):
    """
    Given: An Okta Client is initialized with OAuth
    When: Making an API call with OAuth authentication
    Then: Assure the call is made with the JWT token properly used in the 'Authorization' header.
    """
    client = OktaClient(
        base_url='https://test.url',
        api_token='X',
        auth_type=AuthType.OAUTH,
        client_id='X',
        scopes=['X'],
        private_key='X',
        jwt_algorithm=JWTAlgorithm.RS256
    )

    mocker.patch.object(client, 'get_token', return_value='JWT_TOKEN')
    base_client_http_request_mock = mocker.patch.object(client, '_http_request')
    client.http_request(
        auth_type=AuthType.OAUTH,
        full_url='https://test.url',
        method='GET',
        headers={"test_header": "test_value"},
    )

    assert base_client_http_request_mock.call_count == 1
    assert base_client_http_request_mock.call_args.kwargs == {
        'full_url': 'https://test.url',
        'headers': {
            'Authorization': 'Bearer JWT_TOKEN',
            'test_header': 'test_value',
        },
        'method': 'GET',
    }


def test_reset_integration_context(mocker):
    """
    Given: A user want to reset the integration context
    When: Running the 'reset_integration_context' function
    Then: Assure that the integration context is reset.
    """
    import OktaApiModule

    set_integration_context_mock = mocker.patch.object(OktaApiModule, 'set_integration_context')
    reset_integration_context()

    assert set_integration_context_mock.call_count == 1
    assert set_integration_context_mock.call_args.args[0] == {}
