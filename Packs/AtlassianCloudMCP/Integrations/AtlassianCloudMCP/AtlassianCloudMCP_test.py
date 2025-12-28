import pytest
from pytest_mock import MockerFixture
from AtlassianCloudMCP import main
import demistomock as demisto


class TestMain:
    """Unit tests for the main function of AtlassianCloudMCP."""

    @pytest.mark.asyncio
    async def test_test_module_command(self, mocker: MockerFixture):
        """Given: The test-module command is called.
        When: Main function processes the command.
        Then: A DemistoException is raised indicating test module is unavailable.
        """
        mocker.patch.object(demisto, "params", return_value={"auth_code": {"password": "test_code"}})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="test-module")
        mock_return_error = mocker.patch("AtlassianCloudMCP.return_error")

        await main()

        mock_return_error.assert_called_once()
        error_call = mock_return_error.call_args[0][0]
        assert "Test module is unavailable for this integration" in error_call

    @pytest.mark.asyncio
    async def test_list_tools_command(self, mocker: MockerFixture):
        """Given: The list-tools command is called with valid auth code.
        When: Main function processes the command.
        Then: The client's list_tools method is called and results are returned.
        """

        async def mock_list_tools():
            return {"tools": []}

        mock_client = mocker.MagicMock()
        mock_client.list_tools = mock_list_tools
        mocker.patch("AtlassianCloudMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value={"auth_code": {"password": "test_code"}})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="list-tools")
        mock_return_results = mocker.patch("AtlassianCloudMCP.return_results")

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

        mock_client = mocker.MagicMock()
        mock_client.call_tool = mock_call_tool
        mocker.patch("AtlassianCloudMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value={"auth_code": {"password": "test_code"}})
        mocker.patch.object(demisto, "args", return_value={"name": "test_tool", "arguments": '{"param": "value"}'})
        mocker.patch.object(demisto, "command", return_value="call-tool")
        mock_return_results = mocker.patch("AtlassianCloudMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with({"result": "success"})

    @pytest.mark.asyncio
    async def test_auth_test_command(self, mocker: MockerFixture):
        """Given: The atlassian-cloud-mcp-auth-test command is called.
        When: Main function processes the command.
        Then: The client's test_connection method is called with auth_test=True.
        """

        async def mock_test_connection(auth_test=False):
            return {"status": "authenticated"}

        mock_client = mocker.MagicMock()
        mock_client.test_connection = mock_test_connection
        mocker.patch("AtlassianCloudMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value={"auth_code": {"password": "test_code"}})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="atlassian-cloud-mcp-auth-test")
        mock_return_results = mocker.patch("AtlassianCloudMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with({"status": "authenticated"})

    @pytest.mark.asyncio
    async def test_generate_login_url_command(self, mocker: MockerFixture):
        """Given: The atlassian-cloud-mcp-generate-login-url command is called.
        When: Main function processes the command.
        Then: The generate_login_url function is called and results are returned.
        """

        async def mock_generate_login_url(*args, **kwargs):
            return {"login_url": "https://example.com"}

        mock_client = mocker.MagicMock()
        mocker.patch("AtlassianCloudMCP.Client", return_value=mock_client)
        mocker.patch("AtlassianCloudMCP.generate_login_url", side_effect=mock_generate_login_url)
        mocker.patch.object(demisto, "params", return_value={"auth_code": {"password": "test_code"}})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="atlassian-cloud-mcp-generate-login-url")
        mock_return_results = mocker.patch("AtlassianCloudMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with({"login_url": "https://example.com"})

    @pytest.mark.asyncio
    async def test_unknown_command(self, mocker: MockerFixture):
        """Given: An unknown command is called.
        When: Main function processes the command.
        Then: A NotImplementedError is raised and return_error is called.
        """
        mocker.patch.object(demisto, "params", return_value={"auth_code": {"password": "test_code"}})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="unknown-command")
        mock_return_error = mocker.patch("AtlassianCloudMCP.return_error")

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

        async def mock_list_tools_with_error():
            raise Exception("Connection failed")

        mock_client = mocker.MagicMock()
        mock_client.list_tools = mock_list_tools_with_error
        mocker.patch("AtlassianCloudMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value={"auth_code": {"password": "test_code"}})
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="list-tools")
        mock_return_error = mocker.patch("AtlassianCloudMCP.return_error")

        await main()

        mock_return_error.assert_called_once()
        error_call = mock_return_error.call_args[0][0]
        assert "Failed to execute list-tools command" in error_call
        assert "Connection failed" in error_call
