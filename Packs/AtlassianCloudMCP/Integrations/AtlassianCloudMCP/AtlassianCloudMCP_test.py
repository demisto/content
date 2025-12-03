import traceback

from pytest_mock import MockerFixture
import pytest
from unittest.mock import Mock, AsyncMock
from CommonServerPython import EntryType, CommandResults, DemistoException

import sys
import time

from AtlassianCloudMCP import (
    extract_root_error_message,
    url_origin,
    update_integration_context_oauth_flow,
    OAuthHandler,
    Client,
    generate_login_url,
)

# ExceptionGroup is new in Python 3.11, so we define it for older versions for testing purposes
if sys.version_info < (3, 11):  # noqa: UP036

    class ExceptionGroup(Exception):
        def __init__(self, message, exceptions):
            super().__init__(message)
            self.exceptions = exceptions

    class BaseExceptionGroup(BaseException):
        def __init__(self, message, exceptions):
            super().__init__(message)
            self.exceptions = exceptions


# --- Utility Function Tests ---


def test_extract_root_error_message_with_nested_exception_group():
    """
    Given: A nested ExceptionGroup containing a ValueError as the first inner exception.
    When: extract_root_error_message is called with the nested exception group.
    Then: The root ValueError message should be extracted and formatted.
    """
    inner_exception = ValueError("This is the root cause")
    exception_group = ExceptionGroup("Outer group", [inner_exception, RuntimeError("Another error")])

    result = extract_root_error_message(exception_group)

    assert "ValueError: This is the root cause" in result


def test_extract_root_error_message_with_base_exception_group():
    """
    Given: A BaseExceptionGroup containing a KeyError as the first inner exception.
    When: extract_root_error_message is called with the base exception group.
    Then: The root KeyError message should be extracted and formatted.
    """
    inner_exception = KeyError("missing_key")
    base_exception_group = BaseExceptionGroup("Base group", [inner_exception])

    result = extract_root_error_message(base_exception_group)

    assert "KeyError: 'missing_key'" in result


def test_extract_root_error_message_with_regular_exception():
    """
    Given: A regular RuntimeError exception with a specific message.
    When: extract_root_error_message is called with the regular exception.
    Then: The exception message should be formatted using traceback.format_exception_only.
    """
    exception = RuntimeError("Something went wrong")

    result = extract_root_error_message(exception)

    expected = "".join(traceback.format_exception_only(type(exception), exception))
    assert result == expected
    assert "RuntimeError: Something went wrong" in result


def test_extract_root_error_message_with_deeply_nested_exception_group():
    """
    Given: A deeply nested ExceptionGroup containing multiple levels of exception groups.
    When: extract_root_error_message is called with the outermost exception group.
    Then: The deepest nested exception should be extracted and formatted.
    """
    deepest_exception = ConnectionError("Network timeout")
    middle_group = ExceptionGroup("Middle level", [deepest_exception])
    outer_group = ExceptionGroup("Outer level", [middle_group])

    result = extract_root_error_message(outer_group)

    assert "ConnectionError: Network timeout" in result


def test_url_origin_join():
    """
    Given: A base URL with an existing path.
    When: url_origin is called to extract the origin.
    Then: Only the origin (scheme and netloc) should be returned.
    """
    base_url = "https://example.com/some/path?query=param"
    result = url_origin(base_url)
    assert result == "https://example.com"


def test_url_origin_join_with_port():
    """
    Given: A base URL with port and query parameters.
    When: url_origin is called to extract the origin.
    Then: The result should contain only the scheme, netloc with port.
    """
    base_url = "https://example.com:8080/old/path?query=value#fragment"
    result = url_origin(base_url)
    assert result == "https://example.com:8080"


def test_update_integration_context_oauth_flow_basic(mocker: MockerFixture):
    """
    Given: OAuth flow data to be stored.
    When: update_integration_context_oauth_flow is called.
    Then: The integration context should be updated with the provided data after removing empty elements.
    """
    mock_get_context = mocker.patch("AtlassianCloudMCP.get_integration_context")
    mock_set_context = mocker.patch("AtlassianCloudMCP.set_integration_context")
    mock_remove_empty = mocker.patch("AtlassianCloudMCP.remove_empty_elements")

    existing_context = {"existing_key": "existing_value"}
    mock_get_context.return_value = existing_context

    oauth_data = {"access_token": "token123", "expires_in": 3600, "empty_field": None}
    cleaned_data = {"access_token": "token123", "expires_in": 3600}
    mock_remove_empty.return_value = cleaned_data

    update_integration_context_oauth_flow(oauth_data)

    mock_set_context.assert_called_once()
    call_args = mock_set_context.call_args[0][0]
    assert call_args["existing_key"] == "existing_value"
    assert call_args["access_token"] == "token123"


def test_update_integration_context_oauth_flow_overwrites_existing_keys(mocker: MockerFixture):
    """
    Given: OAuth data that contains keys already present in the existing integration context.
    When: update_integration_context_oauth_flow is called.
    Then: The existing keys should be overwritten with the new values from the OAuth data.
    """
    mock_get_context = mocker.patch("AtlassianCloudMCP.get_integration_context")
    mock_set_context = mocker.patch("AtlassianCloudMCP.set_integration_context")
    mock_remove_empty = mocker.patch("AtlassianCloudMCP.remove_empty_elements")

    existing_context = {"access_token": "old_token", "refresh_token": "old_refresh"}
    mock_get_context.return_value = existing_context

    oauth_data = {"access_token": "new_token", "expires_in": 7200}
    mock_remove_empty.return_value = oauth_data

    update_integration_context_oauth_flow(oauth_data)

    call_args = mock_set_context.call_args[0][0]
    assert call_args["access_token"] == "new_token"
    assert call_args["refresh_token"] == "old_refresh"
    assert call_args["expires_in"] == 7200


# --- Fixtures for OAuthHandler and Client Tests ---


@pytest.fixture
def mock_oauth_handler() -> OAuthHandler:
    """Fixture to create a standard, parameterized OAuthHandler instance."""
    return OAuthHandler(
        base_url="https://api.example.com",
        auth_code="test_auth_code",
    )


@pytest.fixture
def mock_client_instance() -> Client:
    """Fixture to create a standard, parameterized Client instance (configured for Basic Auth)."""
    return Client(
        base_url="https://api.example.com",
        auth_code="test_auth_code",
    )


class TestOAuthHandler:
    def test_oauth_handler_initialization(self, mock_oauth_handler: OAuthHandler):
        """
        Given: Valid OAuth configuration parameters.
        When: OAuthHandler is instantiated.
        Then: All instance variables should be set correctly.
        """
        assert mock_oauth_handler.base_url == "https://api.example.com"
        assert mock_oauth_handler.auth_code == "test_auth_code"

    @pytest.mark.asyncio
    async def test_oauth_register_client_success(self, mocker: MockerFixture, mock_oauth_handler: OAuthHandler):
        """
        Given: Successful client registration response.
        When: _oauth_register_client is called.
        Then: The client_id and client_secret should be returned.
        """
        mock_response = Mock(is_success=True)
        mock_response.json.return_value = {"client_id": "registered_client_123", "client_secret": "registered_secret_456"}

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        mocker.patch("AtlassianCloudMCP.httpx.AsyncClient", return_value=mock_client)

        registration_metadata = {"registration_endpoint": "https://auth.example.com/register"}

        client_id, client_secret = await mock_oauth_handler._oauth_register_client(registration_metadata)

        assert client_id == "registered_client_123"
        assert client_secret == "registered_secret_456"
        mock_client.post.assert_called_once()

    def test_pkce_challenge_generates_valid_verifier_and_challenge(self, mock_oauth_handler: OAuthHandler):
        """
        Given: OAuthHandler instance.
        When: pkce_challenge is called.
        Then: A valid code_verifier and corresponding S256 code_challenge are returned.
        """
        code_verifier, code_challenge = mock_oauth_handler.pkce_challenge()

        assert isinstance(code_verifier, str)
        assert len(code_verifier) == 43
        assert len(code_challenge) == 43
        assert "=" not in code_verifier
        assert "=" not in code_challenge

    def test_create_authorization_url_with_pkce_parameters(self, mocker: MockerFixture, mock_oauth_handler: OAuthHandler):
        """
        Given: PKCE and state parameters.
        When: _create_authorization_url is called.
        Then: The URL should contain all required OAuth, PKCE, and state parameters.
        """
        mocker.patch("AtlassianCloudMCP.demisto.debug")

        result = mock_oauth_handler._create_authorization_url(
            authorization_endpoint="https://auth.example.com/authorize",
            client_id="test_client_id",
            code_challenge="test_code_challenge_123",
            state="random_state_value",
        )

        assert "code_challenge=test_code_challenge_123" in result
        assert "code_challenge_method=S256" in result
        assert "state=random_state_value" in result
        assert "redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2Fcallback" in result

    @pytest.mark.asyncio
    async def test_authorization_code_flow_success(self, mocker: MockerFixture, mock_oauth_handler: OAuthHandler):
        """
        Given: A valid authorization code.
        When: The authorization code flow is executed successfully.
        Then: New access token, refresh token, and expiry are returned.
        """
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "access_token": "auth_code_access_token",
            "refresh_token": "auth_code_refresh_token",
            "expires_in": 7200,
        }
        mock_response.raise_for_status.return_value = None

        mock_client = mocker.Mock()
        mock_client.post = mocker.AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = mocker.AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        mocker.patch("AtlassianCloudMCP.httpx.AsyncClient", return_value=mock_client)
        integration_context = {
            "token_endpoint": "https://auth.example.com/token",
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
        }
        access_token, refresh_token, expires_in = await mock_oauth_handler.get_authorization_code_token(integration_context)

        assert access_token == "auth_code_access_token"
        assert refresh_token == "auth_code_refresh_token"
        assert expires_in == 7200

    @pytest.mark.asyncio
    async def test_missing_auth_code_error(self, mock_oauth_handler: OAuthHandler):
        """
        Given: No refresh token is provided and auth_code is missing.
        When: get_authorization_code_token is called.
        Then: A ValueError is raised.
        """
        mock_oauth_handler.auth_code = ""

        with pytest.raises(DemistoException) as exc_info:
            await mock_oauth_handler.get_authorization_code_token({})

        assert "OAuth context is missing." in str(exc_info.value)


class TestClient:
    def test_client_initialization_basic(self, mock_client_instance: Client):
        """
        Given: Valid parameters for creating a Client instance.
        When: Client is instantiated.
        Then: All instance variables should be set correctly and OAuthHandler initialized.
        """
        client = mock_client_instance
        assert client.base_url == "https://api.example.com"
        assert isinstance(client._oauth_handler, OAuthHandler)

    @pytest.mark.asyncio
    async def test_generate_oauth_headers_with_valid_existing_token(self, mocker: MockerFixture, mock_client_instance):
        """
        Given: A Client with OAuth config and an existing valid access token in integration context.
        When: _generate_oauth_headers is called.
        Then: The method should return Authorization headers with the existing token.
        """
        mocker.patch(
            "AtlassianCloudMCP.get_integration_context",
            return_value={
                "access_token": "existing_valid_token",
                "expires_in": time.time() + 3600,
            },
        )
        mocker.patch("AtlassianCloudMCP.demisto.debug")

        client = mock_client_instance

        headers = await client._generate_oauth_headers()

        assert headers["Authorization"] == "Bearer existing_valid_token"

    @pytest.mark.asyncio
    async def test_list_tools_success(self, mocker: MockerFixture, mock_client_instance: Client):
        """
        Given: A Client instance and mocked successful MCP session that returns tools.
        When: list_tools is called.
        Then: The method should return CommandResults with readable output and tool data.
        """
        mocker.patch.object(Client, "_generate_oauth_headers", return_value={"Authorization": "Bearer test-token"})
        mock_session = mocker.MagicMock()
        mock_session.initialize = mocker.AsyncMock()

        mock_tool1 = Mock(name="search_tool")
        mock_tool2 = Mock(name="analysis_tool")
        mock_tools = Mock(tools=[mock_tool1, mock_tool2])
        mock_session.list_tools = mocker.AsyncMock(return_value=mock_tools)

        # FIX: Explicitly mock streamablehttp_client context manager return value
        mock_streamable_client = mocker.patch("AtlassianCloudMCP.streamablehttp_client")
        mock_streamable_client.return_value.__aenter__ = mocker.AsyncMock(return_value=("r", "w", None))
        mock_streamable_client.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

        # Mock the ClientSession context manager return value
        mock_client_session = mocker.patch("AtlassianCloudMCP.ClientSession")
        mock_client_session.return_value.__aenter__ = mocker.AsyncMock(return_value=mock_session)
        mock_client_session.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

        result = await mock_client_instance.list_tools()

        assert isinstance(result, CommandResults)
        assert "Available 2 tools:" in result.readable_output
        assert result.outputs_prefix == "ListTools.Tools"
        mock_session.list_tools.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_tool_success(self, mocker: MockerFixture, mock_client_instance: Client):
        """
        Given: A client with valid configuration and a successful MCP session response.
        When: Calling call_tool with valid arguments.
        Then: Returns a CommandResults object with the tool execution results and NOTE entry type.
        """
        mock_session = mocker.AsyncMock()
        mock_result = mocker.MagicMock(isError=False)
        mock_result.model_dump.return_value = {"content": {"status": "ok"}}
        mock_session.call_tool.return_value = mock_result
        mock_session.initialize = mocker.AsyncMock()

        # FIX: Explicitly mock streamablehttp_client context manager return value
        mock_streamable_client = mocker.patch("AtlassianCloudMCP.streamablehttp_client")
        mock_streamable_client.return_value.__aenter__ = mocker.AsyncMock(return_value=(None, None, None))
        mock_streamable_client.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

        # Mock the ClientSession context manager return value
        mock_client_session = mocker.patch("AtlassianCloudMCP.ClientSession")
        mock_client_session.return_value.__aenter__ = mocker.AsyncMock(return_value=mock_session)
        mock_client_session.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

        mocker.patch.object(mock_client_instance, "_generate_oauth_headers", return_value={})
        mocker.patch("AtlassianCloudMCP.tableToMarkdown", return_value="Tool executed successfully")

        result = await mock_client_instance.call_tool("test_tool", '{"param1": "value1"}')

        assert isinstance(result, CommandResults)
        assert result.entry_type == EntryType.NOTE
        mock_session.call_tool.assert_called_once_with("test_tool", {"param1": "value1"})


# --- Command Function Tests ---


@pytest.mark.asyncio
async def test_generate_login_url_authorization_code(mocker: MockerFixture, mock_oauth_handler: OAuthHandler):
    """
    Given: An OAuthHandler instance and authorization code flow auth type.
    When: generate_login_url is called with authorization endpoint.
    Then: Returns CommandResults with authorization code flow login URL and instructions.
    """
    # FIX: Patch the method on the real fixture object to assign a return value
    mocker.patch.object(
        mock_oauth_handler,
        "generate_dynamic_registration_login_url",
        return_value=("https://auth.example.com/oauth/authorize?client_id=123", {}),
    )

    result = await generate_login_url(mock_oauth_handler)

    assert isinstance(result, CommandResults)
    assert "https://auth.example.com/oauth/authorize?client_id=123" in result.readable_output
    mock_oauth_handler.generate_dynamic_registration_login_url.assert_called_once()
