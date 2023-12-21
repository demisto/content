from freezegun import freeze_time
from pytest_mock import MockerFixture
from requests_mock import MockerCore
from AkamaiGuardicoreApiModule import AkamaiGuardicoreClient


MockClient = AkamaiGuardicoreClient(
    username="username",
    password="password",
    base_url="https://example.akamai.com",
    verify=False,
    proxy=False,
)

TEST_TOKEN = "1.eyJleHAiOiAxNjI1NjYxMDc3fQ=="


def test_login_valid_token(mocker: MockerFixture):
    """
    Given:
        A client with a valid token in integration context
    When:
        login() is called
    Then:
        It should use the existing token and not generate a new one
    """
    client = MockClient
    client.generate_new_token = mocker.Mock()
    mocker.patch.object(
        AkamaiGuardicoreClient, "_is_access_token_valid", return_value=True
    )
    mocker.patch(
        "AkamaiGuardicoreApiModule.get_integration_context",
        return_value={"access_token": "token"},
    )

    client.login()

    client.generate_new_token.assert_not_called()


def test_login_invalid_token(mocker: MockerFixture):
    """
    Given:
        A client with an invalid token in integration context
    When:
        login() is called
    Then:
        It should generate a new token
    """
    client = MockClient
    client.generate_new_token = mocker.Mock()
    mocker.patch.object(
        AkamaiGuardicoreClient, "_is_access_token_valid", return_value=False
    )

    client.login()

    client.generate_new_token.assert_called_once()


@freeze_time("2020-01-01T00:00:00Z")
def test_is_access_token_valid_true():
    """
    Given:
        Valid token and expiration in context
    When:
        _is_access_token_valid() is called
    Then:
        It should return True
    """
    client = MockClient
    assert client._is_access_token_valid(
        {"access_token": "token", "expires_in": "2020-01-02T00:00:00Z"}
    )


@freeze_time("2020-01-02T00:00:00Z")
def test_is_access_token_valid_false():
    """
    Given:
        Valid token and expired expiration in context
    When:
        _is_access_token_valid() is called
    Then:
        It should return False
    """
    client = MockClient
    assert not client._is_access_token_valid(
        {"access_token": "token", "expires_in": "2020-01-01T00:00:00Z"}
    )


def test_get_jwt_expiration_valid_token():
    """
    Given:
        A valid JWT token as input
    When:
        get_jwt_expiration is called
    Then:
        It should return the expiration time extracted from the token
    """
    client = MockClient

    expiration = client.get_jwt_expiration(TEST_TOKEN)
    assert expiration == 1625661077


def test_get_jwt_expiration_invalid_token():
    """
    Given:
        An invalid JWT token as input
    When:
        get_jwt_expiration is called
    Then:
        It should return 0
    """
    client = MockClient

    sample_token = "invalid"
    expiration = client.get_jwt_expiration(sample_token)
    assert expiration == 0


def test_authenticate(requests_mock: MockerCore):
    """
    Given:
        username and password
    When:
        We mock the authentication to the integration api endpoint.
    Then:
        Validate that the access_token is returned correctly.
    """
    requests_mock.post(
        "https://api.guardicoreexample.com/api/v3.0/authenticate",
        json={"access_token": TEST_TOKEN},
    )
    client = AkamaiGuardicoreClient(
        base_url="https://api.guardicoreexample.com/api/v3.0",
        verify=False,
        proxy=False,
        username="test",
        password="test",
    )
    client.login()
    assert client.access_token == TEST_TOKEN
