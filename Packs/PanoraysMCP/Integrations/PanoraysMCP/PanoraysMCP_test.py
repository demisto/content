import pytest
from pytest_mock import MockerFixture
from unittest.mock import AsyncMock

import demistomock as demisto
from PanoraysMCP import (
    main,
    validate_required_params,
    PANORAYS_MCP_URL,
    PANORAYS_AUTHORIZATION_ENDPOINT,
    PANORAYS_TOKEN_ENDPOINT,
    PANORAYS_SCOPE,
    SERVER_NAME,
)


BEARER_PARAMS = {
    "auth_type": "Bearer",
    "token": {"password": "test_token"},
}

OAUTH_PARAMS = {
    "auth_type": "OAuth 2.0 Authorization Code",
    "oauth_credentials": {"identifier": "test_client_id", "password": "test_client_secret"},
    "auth_code": {"password": "test%2Fauth_code"},
    "redirect_uri": "https://oproxy.demisto.ninja/authcode",
}


def mock_main_dependencies(mocker: MockerFixture, params: dict, command: str, args: dict | None = None) -> tuple:
    client_instance = AsyncMock()
    client_class = mocker.patch("PanoraysMCP.Client", return_value=client_instance)
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value=args or {})
    mocker.patch.object(demisto, "command", return_value=command)
    return_results = mocker.patch("PanoraysMCP.return_results")
    return_error = mocker.patch("PanoraysMCP.return_error")
    return client_class, client_instance, return_results, return_error


class TestValidateRequiredParams:
    """Unit tests for validate_required_params."""

    def test_valid_bearer_params_passes(self):
        """Given: Bearer authentication with a token.
        When: validate_required_params is called.
        Then: No exception is raised.
        """
        validate_required_params("Bearer", "token", "", "")

    def test_valid_oauth_params_passes(self):
        """Given: OAuth authentication with a Client ID and Client Secret.
        When: validate_required_params is called.
        Then: No exception is raised.
        """
        validate_required_params("OAuth 2.0 Authorization Code", "", "cid", "csecret")

    @pytest.mark.parametrize("auth_type", ["", "Basic", "OAuth 2.0 Dynamic Client Registration"])
    def test_unsupported_auth_type_raises(self, auth_type: str):
        """Given: An authentication type that Panorays does not support.
        When: validate_required_params is called.
        Then: A ValueError is raised mentioning the unsupported type.
        """
        with pytest.raises(ValueError, match="Unsupported authentication type"):
            validate_required_params(auth_type, "token", "cid", "csecret")

    def test_bearer_missing_token_raises(self):
        """Given: Bearer authentication without a token.
        When: validate_required_params is called.
        Then: A ValueError is raised mentioning the API token.
        """
        with pytest.raises(ValueError, match="API Token is required"):
            validate_required_params("Bearer", "", "cid", "csecret")

    @pytest.mark.parametrize("client_id, client_secret", [("", "csecret"), ("cid", ""), ("", "")])
    def test_oauth_missing_credentials_raises(self, client_id: str, client_secret: str):
        """Given: OAuth authentication with a missing Client ID or Client Secret.
        When: validate_required_params is called.
        Then: A ValueError is raised mentioning the OAuth credentials.
        """
        with pytest.raises(ValueError, match="Client ID and Client Secret"):
            validate_required_params("OAuth 2.0 Authorization Code", "token", client_id, client_secret)


class TestMain:
    """Unit tests for the main function of PanoraysMCP."""

    @pytest.mark.asyncio
    async def test_client_built_for_bearer(self, mocker: MockerFixture):
        """Given: Bearer authentication parameters.
        When: Main function processes a command.
        Then: The client is created with the Panorays MCP URL and the token.
        """
        client_class, _, _, _ = mock_main_dependencies(mocker, BEARER_PARAMS, "list-tools")

        await main()

        client_kwargs = client_class.call_args.kwargs
        assert client_kwargs["base_url"] == PANORAYS_MCP_URL
        assert client_kwargs["auth_type"] == "Bearer"
        assert client_kwargs["token"] == "test_token"

    @pytest.mark.asyncio
    async def test_client_built_for_oauth(self, mocker: MockerFixture):
        """Given: OAuth authentication parameters with a URL-encoded authorization code.
        When: Main function processes a command.
        Then: The client is created with the Panorays OAuth endpoints, scope and the decoded authorization code.
        """
        client_class, _, _, _ = mock_main_dependencies(mocker, OAUTH_PARAMS, "list-tools")

        await main()

        client_kwargs = client_class.call_args.kwargs
        assert client_kwargs["base_url"] == PANORAYS_MCP_URL
        assert client_kwargs["auth_type"] == "OAuth 2.0 Authorization Code"
        assert client_kwargs["client_id"] == "test_client_id"
        assert client_kwargs["client_secret"] == "test_client_secret"
        assert client_kwargs["auth_code"] == "test/auth_code"
        assert client_kwargs["token_endpoint"] == PANORAYS_TOKEN_ENDPOINT
        assert client_kwargs["scope"] == PANORAYS_SCOPE
        assert client_kwargs["redirect_uri"] == OAUTH_PARAMS["redirect_uri"]

    @pytest.mark.asyncio
    async def test_redirect_uri_defaults_when_empty(self, mocker: MockerFixture):
        """Given: OAuth authentication parameters with an empty redirect URI.
        When: Main function processes a command.
        Then: The client is created with the default redirect URI.
        """
        params = OAUTH_PARAMS | {"redirect_uri": ""}
        client_class, _, _, _ = mock_main_dependencies(mocker, params, "list-tools")

        await main()

        assert client_class.call_args.kwargs["redirect_uri"] == "https://oproxy.demisto.ninja/authcode"

    @pytest.mark.asyncio
    async def test_auth_type_defaults_to_bearer_when_empty(self, mocker: MockerFixture):
        """Given: Bearer authentication parameters with an empty authentication type.
        When: Main function processes a command.
        Then: The client is created with Bearer authentication, matching the YAML default.
        """
        params = BEARER_PARAMS | {"auth_type": ""}
        client_class, _, _, _ = mock_main_dependencies(mocker, params, "list-tools")

        await main()

        assert client_class.call_args.kwargs["auth_type"] == "Bearer"

    @pytest.mark.asyncio
    async def test_test_module_bearer(self, mocker: MockerFixture):
        """Given: The test-module command is called with Bearer authentication.
        When: Main function processes the command.
        Then: The client's test_connection method is called and its result is returned.
        """
        _, client_instance, return_results, _ = mock_main_dependencies(mocker, BEARER_PARAMS, "test-module")
        client_instance.test_connection.return_value = "ok"

        await main()

        client_instance.test_connection.assert_awaited_once_with()
        return_results.assert_called_once_with("ok")

    @pytest.mark.asyncio
    async def test_test_module_oauth(self, mocker: MockerFixture):
        """Given: The test-module command is called with OAuth authentication.
        When: Main function processes the command.
        Then: return_error is called with a message directing the user to the auth-test command.
        """
        _, client_instance, _, return_error = mock_main_dependencies(mocker, OAUTH_PARAMS, "test-module")

        await main()

        client_instance.test_connection.assert_not_awaited()
        error_message = return_error.call_args[0][0]
        assert "Test module is unavailable" in error_message
        assert "panorays-mcp-auth-test" in error_message

    @pytest.mark.asyncio
    async def test_list_tools(self, mocker: MockerFixture):
        """Given: The list-tools command is called.
        When: Main function processes the command.
        Then: The client's list_tools method is called with the Panorays server name.
        """
        _, client_instance, return_results, _ = mock_main_dependencies(mocker, BEARER_PARAMS, "list-tools")
        client_instance.list_tools.return_value = {"tools": []}

        await main()

        client_instance.list_tools.assert_awaited_once_with(SERVER_NAME)
        return_results.assert_called_once_with({"tools": []})

    @pytest.mark.asyncio
    async def test_call_tool_with_arguments(self, mocker: MockerFixture):
        """Given: The call-tool command is called with a tool name and arguments.
        When: Main function processes the command.
        Then: The client's call_tool method is called with the provided parameters.
        """
        args = {"name": "example_tool", "arguments": '{"param": "value"}'}
        _, client_instance, return_results, _ = mock_main_dependencies(mocker, BEARER_PARAMS, "call-tool", args)
        client_instance.call_tool.return_value = {"result": "success"}

        await main()

        client_instance.call_tool.assert_awaited_once_with("example_tool", '{"param": "value"}')
        return_results.assert_called_once_with({"result": "success"})

    @pytest.mark.asyncio
    async def test_call_tool_without_arguments(self, mocker: MockerFixture):
        """Given: The call-tool command is called with only a tool name.
        When: Main function processes the command.
        Then: The client's call_tool method is called with an empty arguments string.
        """
        _, client_instance, return_results, _ = mock_main_dependencies(
            mocker, BEARER_PARAMS, "call-tool", {"name": "example_tool"}
        )
        client_instance.call_tool.return_value = {"result": "ok"}

        await main()

        client_instance.call_tool.assert_awaited_once_with("example_tool", "")
        return_results.assert_called_once_with({"result": "ok"})

    @pytest.mark.asyncio
    async def test_auth_test(self, mocker: MockerFixture):
        """Given: The panorays-mcp-auth-test command is called.
        When: Main function processes the command.
        Then: The client's test_connection method is called with auth_test=True.
        """
        _, client_instance, return_results, _ = mock_main_dependencies(mocker, OAUTH_PARAMS, "panorays-mcp-auth-test")
        client_instance.test_connection.return_value = {"status": "authenticated"}

        await main()

        client_instance.test_connection.assert_awaited_once_with(auth_test=True)
        return_results.assert_called_once_with({"status": "authenticated"})

    @pytest.mark.asyncio
    async def test_generate_login_url(self, mocker: MockerFixture):
        """Given: The panorays-mcp-generate-login-url command is called with OAuth authentication.
        When: Main function processes the command.
        Then: generate_login_url is called with the Panorays authorization endpoint and troubleshooting enabled.
        """
        _, client_instance, return_results, _ = mock_main_dependencies(mocker, OAUTH_PARAMS, "panorays-mcp-generate-login-url")
        generate_login_url = mocker.patch("PanoraysMCP.generate_login_url", return_value={"login_url": "url"})

        await main()

        generate_login_url.assert_awaited_once_with(
            client_instance._oauth_handler,
            auth_type="OAuth 2.0 Authorization Code",
            authorization_endpoint=PANORAYS_AUTHORIZATION_ENDPOINT,
            redirect_uri=OAUTH_PARAMS["redirect_uri"],
            troubleshooting_redirect=True,
        )
        return_results.assert_called_once_with({"login_url": "url"})

    @pytest.mark.asyncio
    async def test_unknown_command(self, mocker: MockerFixture):
        """Given: An unknown command is called.
        When: Main function processes the command.
        Then: return_error is called with a not implemented message.
        """
        _, _, _, return_error = mock_main_dependencies(mocker, BEARER_PARAMS, "unknown-command")

        await main()

        assert "Command unknown-command is not implemented" in return_error.call_args[0][0]

    @pytest.mark.asyncio
    async def test_exception_handling_closes_client(self, mocker: MockerFixture):
        """Given: The client raises an exception while processing a command.
        When: Main function processes the command.
        Then: return_error is called with the error message and the client is closed.
        """
        _, client_instance, _, return_error = mock_main_dependencies(mocker, BEARER_PARAMS, "list-tools")
        client_instance.list_tools.side_effect = Exception("Connection failed")

        await main()

        error_message = return_error.call_args[0][0]
        assert "Failed to execute list-tools command" in error_message
        assert "Connection failed" in error_message
        client_instance.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_validation_failure_does_not_create_client(self, mocker: MockerFixture):
        """Given: Bearer authentication is selected without a token.
        When: Main function processes any command.
        Then: return_error is called with the validation message and no client is created.
        """
        params = BEARER_PARAMS | {"token": {"password": ""}}
        client_class, _, _, return_error = mock_main_dependencies(mocker, params, "list-tools")

        await main()

        assert "API Token is required" in return_error.call_args[0][0]
        client_class.assert_not_called()
