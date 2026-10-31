import pytest
from pytest_mock import MockerFixture
from CommandZeroMCP import main, get_base_url, get_headers
from CommonServerPython import DemistoException
import demistomock as demisto


DEFAULT_PARAMS = {"region": "North America", "api_key": {"password": "test_api_key"}, "org_id": "test-org"}


def mock_client(mocker: MockerFixture, **methods):
    """Patches the MCP Client with a mock exposing the given async methods."""

    async def mock_close():
        pass

    client = mocker.MagicMock()
    client.close = mock_close
    for name, method in methods.items():
        setattr(client, name, method)
    return mocker.patch("CommandZeroMCP.Client", return_value=client)


def mock_command(mocker: MockerFixture, command: str, args: dict | None = None, params: dict | None = None):
    mocker.patch.object(demisto, "params", return_value=DEFAULT_PARAMS if params is None else params)
    mocker.patch.object(demisto, "args", return_value=args or {})
    mocker.patch.object(demisto, "command", return_value=command)


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


class TestGetHeaders:
    """Unit tests for building the request headers."""

    @pytest.mark.parametrize(
        "params, expected_headers",
        [
            ({}, {}),
            ({"org_id": " test-org "}, {"X-Org-ID": "test-org"}),
            ({"custom_headers": "X-Test: value"}, {"X-Test": "value"}),
            (
                {"org_id": "test-org", "custom_headers": "X-Org-ID: other\nX-Test: value"},
                {"X-Org-ID": "test-org", "X-Test": "value"},
            ),
        ],
    )
    def test_get_headers(self, params: dict, expected_headers: dict):
        """Given: Organization ID and custom headers parameters.
        When: Building the request headers.
        Then: The organization ID header is added when set and takes precedence over a custom header with the same name.
        """
        assert get_headers(params) == expected_headers


class TestMain:
    """Unit tests for the main function of CommandZeroMCP."""

    @pytest.mark.asyncio
    async def test_client_configuration(self, mocker: MockerFixture):
        """Given: The European Union region, an API key, and an organization ID.
        When: Main function creates the client.
        Then: The client uses Bearer authentication with the API key, the region URL, and the organization ID header.
        """

        async def mock_test_connection(auth_test=False):
            return "ok"

        client_class = mock_client(mocker, test_connection=mock_test_connection)
        mock_command(mocker, "test-module", params=DEFAULT_PARAMS | {"region": "European Union"})
        mocker.patch("CommandZeroMCP.return_results")

        await main()

        client_kwargs = client_class.call_args.kwargs
        assert client_kwargs["base_url"] == "https://mcp.eu.cmdzero.io/"
        assert client_kwargs["auth_type"] == "Bearer"
        assert client_kwargs["token"] == "test_api_key"
        assert client_kwargs["custom_headers"] == {"X-Org-ID": "test-org"}
        assert client_kwargs["verify"] is True

    @pytest.mark.asyncio
    async def test_test_module_command(self, mocker: MockerFixture):
        """Given: The test-module command is called.
        When: Main function processes the command.
        Then: The connection is tested and 'ok' is returned.
        """

        async def mock_test_connection(auth_test=False):
            return "ok"

        mock_client(mocker, test_connection=mock_test_connection)
        mock_command(mocker, "test-module")
        mock_return_results = mocker.patch("CommandZeroMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with("ok")

    @pytest.mark.asyncio
    async def test_missing_api_key(self, mocker: MockerFixture):
        """Given: No API key is configured.
        When: Main function processes a command.
        Then: An error is returned asking for the API key, and no client is created.
        """
        client_class = mock_client(mocker)
        mock_command(mocker, "test-module", params={"region": "North America"})
        mock_return_error = mocker.patch("CommandZeroMCP.return_error")

        await main()

        assert "An API key is required" in mock_return_error.call_args[0][0]
        client_class.assert_not_called()

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
