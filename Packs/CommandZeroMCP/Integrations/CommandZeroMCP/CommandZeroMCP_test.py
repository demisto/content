import pytest
from pytest_mock import MockerFixture
from CommandZeroMCP import main, get_base_url
from CommonServerPython import CommandResults, DemistoException
import demistomock as demisto


DEFAULT_PARAMS = {"region": "North America", "auth_code": {"password": "test_code"}}


def mock_client(mocker: MockerFixture, **methods):
    """Patches the MCP Client with a mock exposing the given async methods."""

    async def mock_close():
        pass

    client = mocker.MagicMock()
    client.close = mock_close
    for name, method in methods.items():
        setattr(client, name, method)
    return mocker.patch("CommandZeroMCP.Client", return_value=client)


def mock_command(
    mocker: MockerFixture,
    command: str,
    args: dict | None = None,
    params: dict | None = None,
    integration_context: dict | None = None,
):
    """Mocks the command inputs. By default, the instance has a login session with a stored token endpoint."""
    mocker.patch.object(demisto, "params", return_value=params or DEFAULT_PARAMS)
    mocker.patch.object(demisto, "args", return_value=args or {})
    mocker.patch.object(demisto, "command", return_value=command)
    if integration_context is None:
        integration_context = {"token_endpoint": "https://mcp.cmdzero.io/oauth/token"}
    mocker.patch("CommandZeroMCP.get_integration_context", return_value=integration_context)


class TestGetBaseUrl:
    """Unit tests for resolving the Command Zero MCP server URL."""

    @pytest.mark.parametrize(
        "params, expected_url",
        [
            ({}, "https://mcp.cmdzero.io/"),
            ({"region": "North America"}, "https://mcp.cmdzero.io/"),
            ({"region": "European Union"}, "https://mcp.eu.cmdzero.io/"),
            ({"region": "European Union", "server_url": " https://staging.example.com/ "}, "https://staging.example.com/"),
        ],
    )
    def test_get_base_url(self, params: dict, expected_url: str):
        """Given: Region and custom server URL parameters.
        When: Resolving the server URL.
        Then: The custom URL wins when set, otherwise the region URL is used.
        """
        assert get_base_url(params) == expected_url

    def test_get_base_url_unsupported_region(self):
        """Given: An unsupported region.
        When: Resolving the server URL.
        Then: A DemistoException is raised.
        """
        with pytest.raises(DemistoException, match="Unsupported region"):
            get_base_url({"region": "Antarctica"})


class TestMain:
    """Unit tests for the main function of CommandZeroMCP."""

    @pytest.mark.asyncio
    async def test_test_module_command(self, mocker: MockerFixture):
        """Given: The test-module command is called.
        When: Main function processes the command.
        Then: An error is returned indicating test module is unavailable.
        """
        mock_client(mocker)
        mock_command(mocker, "test-module")
        mock_return_error = mocker.patch("CommandZeroMCP.return_error")

        await main()

        assert "Test module is unavailable for this integration" in mock_return_error.call_args[0][0]

    @pytest.mark.asyncio
    async def test_client_configuration(self, mocker: MockerFixture):
        """Given: The European Union region, an encoded auth code, and custom headers.
        When: Main function creates the client.
        Then: The client is created with the region URL, decoded auth code, default redirect URI, and parsed headers.
        """

        async def mock_test_connection(auth_test=False):
            return "ok"

        client_class = mock_client(mocker, test_connection=mock_test_connection)
        params = {
            "region": "European Union",
            "auth_code": {"password": "abc%3D"},
            "custom_headers": "X-Test: value",
        }
        mock_command(mocker, "command-zero-mcp-auth-test", params=params)
        mocker.patch("CommandZeroMCP.return_results")

        await main()

        client_kwargs = client_class.call_args.kwargs
        assert client_kwargs["base_url"] == "https://mcp.eu.cmdzero.io/"
        assert client_kwargs["auth_code"] == "abc="
        assert client_kwargs["redirect_uri"] == "https://oproxy.demisto.ninja/authcode"
        assert client_kwargs["custom_headers"] == {"X-Test": "value"}
        assert client_kwargs["verify"] is True

    @pytest.mark.asyncio
    async def test_list_tools_command(self, mocker: MockerFixture):
        """Given: The list-tools command is called.
        When: Main function processes the command.
        Then: The client's list_tools result is returned.
        """

        async def mock_list_tools(server_name):
            return {"tools": [], "server": server_name}

        mock_client(mocker, list_tools=mock_list_tools)
        mock_command(mocker, "list-tools")
        mock_return_results = mocker.patch("CommandZeroMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with({"tools": [], "server": "Command Zero MCP"})

    @pytest.mark.asyncio
    async def test_call_tool_command(self, mocker: MockerFixture):
        """Given: The call-tool command is called with a tool name and arguments.
        When: Main function processes the command.
        Then: The client's call_tool method is called with the provided parameters.
        """

        async def mock_call_tool(name, arguments):
            return {"name": name, "arguments": arguments}

        mock_client(mocker, call_tool=mock_call_tool)
        mock_command(mocker, "call-tool", args={"name": "get_caller_identity", "arguments": "{}"})
        mock_return_results = mocker.patch("CommandZeroMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with({"name": "get_caller_identity", "arguments": "{}"})

    @pytest.mark.asyncio
    async def test_generate_login_url_command(self, mocker: MockerFixture):
        """Given: The command-zero-mcp-generate-login-url command is called with a custom redirect URI.
        When: Main function processes the command.
        Then: The login URL is generated with Dynamic Client Registration and the custom redirect URI.
        """
        mock_client(mocker)
        mock_generate_login_url = mocker.patch("CommandZeroMCP.generate_login_url", return_value={"login_url": "url"})
        mock_command(mocker, "command-zero-mcp-generate-login-url", params=DEFAULT_PARAMS | {"redirect_uri": "http://localhost"})
        mock_return_results = mocker.patch("CommandZeroMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with({"login_url": "url"})
        assert mock_generate_login_url.call_args.kwargs == {
            "auth_type": "OAuth 2.0 Dynamic Client Registration",
            "redirect_uri": "http://localhost",
        }

    @pytest.mark.asyncio
    async def test_auth_test_without_login_session(self, mocker: MockerFixture):
        """Given: The instance has no login session stored in the integration context.
        When: The command-zero-mcp-auth-test command is called.
        Then: A login URL is generated and returned instead of attempting a token exchange.
        """
        client_class = mock_client(mocker)
        mocker.patch(
            "CommandZeroMCP.generate_login_url",
            return_value=CommandResults(readable_output="### Authorization instructions"),
        )
        mock_command(mocker, "command-zero-mcp-auth-test", integration_context={})
        mock_return_results = mocker.patch("CommandZeroMCP.return_results")

        await main()

        readable_output = mock_return_results.call_args[0][0].readable_output
        assert readable_output.startswith("No Command Zero login session was found for this instance.")
        assert "### Authorization instructions" in readable_output
        client_class.return_value.test_connection.assert_not_called()

    @pytest.mark.asyncio
    async def test_call_tool_without_login_session(self, mocker: MockerFixture):
        """Given: The instance has no login session stored in the integration context.
        When: The call-tool command is called.
        Then: An error is returned instructing the user to generate a login URL.
        """
        mock_client(mocker)
        mock_command(mocker, "call-tool", args={"name": "get_caller_identity"}, integration_context={})
        mock_return_error = mocker.patch("CommandZeroMCP.return_error")

        await main()

        error_message = mock_return_error.call_args[0][0]
        assert "No Command Zero login session was found for this instance" in error_message
        assert "!command-zero-mcp-generate-login-url" in error_message

    @pytest.mark.asyncio
    async def test_unknown_command(self, mocker: MockerFixture):
        """Given: An unknown command is called.
        When: Main function processes the command.
        Then: An error is returned stating the command is not implemented.
        """
        mock_client(mocker)
        mock_command(mocker, "unknown-command")
        mock_return_error = mocker.patch("CommandZeroMCP.return_error")

        await main()

        assert "Command unknown-command is not implemented" in mock_return_error.call_args[0][0]

    @pytest.mark.asyncio
    async def test_exception_handling(self, mocker: MockerFixture):
        """Given: The server connection fails.
        When: Main function processes the list-tools command.
        Then: An error is returned containing the root error message.
        """

        async def mock_list_tools_with_error(server_name):
            raise Exception("Connection failed")

        mock_client(mocker, list_tools=mock_list_tools_with_error)
        mock_command(mocker, "list-tools")
        mock_return_error = mocker.patch("CommandZeroMCP.return_error")

        await main()

        error_message = mock_return_error.call_args[0][0]
        assert "Failed to execute list-tools command" in error_message
        assert "Connection failed" in error_message
