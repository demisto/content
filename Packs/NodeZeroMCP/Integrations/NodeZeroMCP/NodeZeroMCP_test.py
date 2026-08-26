import pytest
from pytest_mock import MockerFixture
from NodeZeroMCP import main, validate_required_params
import demistomock as demisto


def test_validate_required_params_valid():
    """
    Given: A valid base URL.
    When: validate_required_params is called.
    Then: No exception should be raised.
    """
    validate_required_params(base_url="https://mcp.horizon3ai.com")


def test_validate_required_params_missing_base_url():
    """
    Given: An empty base URL.
    When: validate_required_params is called.
    Then: ValueError should be raised.
    """
    with pytest.raises(ValueError, match="Server URL must be provided"):
        validate_required_params(base_url="")


class TestMain:
    """Unit tests for the main function of NodeZeroMCP."""

    @pytest.mark.asyncio
    async def test_test_module_command(self, mocker: MockerFixture):
        """Given: The test-module command is called.
        When: Main function processes the command.
        Then: return_error is called indicating test module is unavailable.
        """

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.close = mock_close
        mocker.patch("NodeZeroMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value={"base_url": "https://mcp.horizon3ai.com"})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="test-module")
        mock_return_error = mocker.patch("NodeZeroMCP.return_error")

        await main()

        mock_return_error.assert_called_once()
        error_call = mock_return_error.call_args[0][0]
        assert "Test module is unavailable" in error_call

    @pytest.mark.asyncio
    async def test_list_tools_command(self, mocker: MockerFixture):
        """Given: The list-tools command is called.
        When: Main function processes the command.
        Then: The client's list_tools method is called and results are returned.
        """

        async def mock_list_tools(server_name):
            return {"tools": []}

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.list_tools = mock_list_tools
        mock_client.close = mock_close
        mocker.patch("NodeZeroMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value={"base_url": "https://mcp.horizon3ai.com"})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="list-tools")
        mock_return_results = mocker.patch("NodeZeroMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with({"tools": []})

    @pytest.mark.asyncio
    async def test_call_tool_command(self, mocker: MockerFixture):
        """Given: The call-tool command is called with tool name and arguments.
        When: Main function processes the command.
        Then: The client's call_tool method is called with the provided parameters.
        """

        async def mock_call_tool(name, arguments):
            return {"result": "success"}

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.call_tool = mock_call_tool
        mock_client.close = mock_close
        mocker.patch("NodeZeroMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value={"base_url": "https://mcp.horizon3ai.com"})
        mocker.patch.object(demisto, "args", return_value={"name": "get_pentest_details", "arguments": '{"limit": 10}'})
        mocker.patch.object(demisto, "command", return_value="call-tool")
        mock_return_results = mocker.patch("NodeZeroMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with({"result": "success"})

    @pytest.mark.asyncio
    async def test_auth_test_command(self, mocker: MockerFixture):
        """Given: The nodezero-mcp-auth-test command is called.
        When: Main function processes the command.
        Then: The client's test_connection method is called with auth_test=True.
        """

        async def mock_test_connection(auth_test=False):
            return {"status": "authenticated"}

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.test_connection = mock_test_connection
        mock_client.close = mock_close
        mocker.patch("NodeZeroMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value={"base_url": "https://mcp.horizon3ai.com"})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="nodezero-mcp-auth-test")
        mock_return_results = mocker.patch("NodeZeroMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with({"status": "authenticated"})

    @pytest.mark.asyncio
    async def test_generate_login_url_command(self, mocker: MockerFixture):
        """Given: The nodezero-mcp-generate-login-url command is called.
        When: Main function processes the command.
        Then: generate_login_url is called and results are returned.
        """

        async def mock_generate_login_url(*args, **kwargs):
            return {"login_url": "https://oauth-proxy.horizon3ai.com/authorize?client_id=abc"}

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.close = mock_close
        mocker.patch("NodeZeroMCP.Client", return_value=mock_client)
        mocker.patch("NodeZeroMCP.generate_login_url", side_effect=mock_generate_login_url)
        mocker.patch.object(demisto, "params", return_value={"base_url": "https://mcp.horizon3ai.com"})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="nodezero-mcp-generate-login-url")
        mock_return_results = mocker.patch("NodeZeroMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with({"login_url": "https://oauth-proxy.horizon3ai.com/authorize?client_id=abc"})

    @pytest.mark.asyncio
    async def test_unknown_command(self, mocker: MockerFixture):
        """Given: An unknown command is called.
        When: Main function processes the command.
        Then: return_error is called with a not-implemented message.
        """

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.close = mock_close
        mocker.patch("NodeZeroMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value={"base_url": "https://mcp.horizon3ai.com"})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="unknown-command")
        mock_return_error = mocker.patch("NodeZeroMCP.return_error")

        await main()

        mock_return_error.assert_called_once()
        error_call = mock_return_error.call_args[0][0]
        assert "Command unknown-command is not implemented" in error_call

    @pytest.mark.asyncio
    async def test_exception_handling(self, mocker: MockerFixture):
        """Given: An exception occurs during command processing.
        When: Main function processes the command.
        Then: The exception is caught and return_error is called with the error message.
        """

        async def mock_list_tools_with_error(server_name):
            raise Exception("Connection failed")

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.list_tools = mock_list_tools_with_error
        mock_client.close = mock_close
        mocker.patch("NodeZeroMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value={"base_url": "https://mcp.horizon3ai.com"})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="list-tools")
        mock_return_error = mocker.patch("NodeZeroMCP.return_error")

        await main()

        mock_return_error.assert_called_once()
        error_call = mock_return_error.call_args[0][0]
        assert "Failed to execute list-tools command" in error_call
        assert "Connection failed" in error_call

    @pytest.mark.asyncio
    async def test_client_closed_on_exception(self, mocker: MockerFixture):
        """Given: An exception occurs during command processing.
        When: Main function processes the command.
        Then: The client's close method is always called in the finally block.
        """
        close_called = []

        async def mock_close():
            close_called.append(True)

        async def mock_list_tools_with_error(server_name):
            raise Exception("Connection failed")

        mock_client = mocker.MagicMock()
        mock_client.list_tools = mock_list_tools_with_error
        mock_client.close = mock_close
        mocker.patch("NodeZeroMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value={"base_url": "https://mcp.horizon3ai.com"})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="list-tools")
        mocker.patch("NodeZeroMCP.return_error")

        await main()

        assert close_called, "client.close() was not called in the finally block"

    @pytest.mark.asyncio
    async def test_missing_base_url_calls_return_error(self, mocker: MockerFixture):
        """Given: Params contain an empty base_url.
        When: Main function processes any command.
        Then: return_error is called due to the ValueError from validate_required_params.
        """
        mocker.patch("NodeZeroMCP.Client")
        mocker.patch.object(demisto, "params", return_value={"base_url": ""})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="list-tools")
        mock_return_error = mocker.patch("NodeZeroMCP.return_error")

        await main()

        mock_return_error.assert_called_once()
        error_call = mock_return_error.call_args[0][0]
        assert "Server URL must be provided" in error_call
