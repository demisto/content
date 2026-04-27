import pytest

from GenericMCP import validate_required_params, AuthMethods


def test_validate_required_params_valid_basic_auth():
    """
    Given: Valid basic authentication parameters.
    When: validate_required_params is called with BASIC auth type.
    Then: No exception should be raised.
    """
    validate_required_params(
        base_url="https://example.com",
        auth_type=AuthMethods.BASIC,
        user_name="testuser",
        password="testpass",
        token="",
        client_id="",
        client_secret="",
    )


def test_validate_required_params_basic_auth_missing_credentials():
    """
    Given: Basic authentication type with missing password.
    When: validate_required_params is called.
    Then: ValueError should be raised.
    """
    with pytest.raises(ValueError, match="Username and Password are required for basic authentication"):
        validate_required_params(
            base_url="https://example.com",
            auth_type=AuthMethods.BASIC,
            user_name="testuser",
            password="",
            token="",
            client_id="",
            client_secret="",
        )


def test_validate_required_params_oauth_missing_credentials():
    """
    Given: OAuth authentication type with missing client_secret.
    When: validate_required_params is called.
    Then: ValueError should be raised requiring Client ID and Client Secret.
    """
    with pytest.raises(ValueError, match="Client ID, Client Secret are required for OAuth authentication"):
        validate_required_params(
            base_url="https://example.com",
            auth_type=AuthMethods.CLIENT_CREDENTIALS,
            user_name="",
            password="",
            token="",
            client_id="test_client_id",
            client_secret="",
        )
