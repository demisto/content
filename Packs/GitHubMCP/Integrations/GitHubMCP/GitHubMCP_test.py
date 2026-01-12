import pytest
from pytest_mock import MockerFixture


from GitHubMCP import main

from unittest.mock import AsyncMock


class TestGitHubMCPMain:
    """Test class for GitHubMCP main function."""

    @pytest.mark.asyncio
    async def test_main_test_module_success(self, mocker: MockerFixture):
        """
        Given: A test-module command with valid parameters and successful client connection.
        When: The main function is called with test-module command.
        Then: The client test_connection method is called and results are returned successfully.
        """

        # Mock demisto functions
        mock_params = mocker.patch("GitHubMCP.demisto.params")
        mock_args = mocker.patch("GitHubMCP.demisto.args")
        mock_command = mocker.patch("GitHubMCP.demisto.command")
        mocker.patch("GitHubMCP.demisto.debug")
        mock_return_results = mocker.patch("GitHubMCP.return_results")
        mock_arg_to_list = mocker.patch("GitHubMCP.argToList")
        mock_arg_to_boolean = mocker.patch("GitHubMCP.argToBoolean")

        # Mock Client class
        mock_client_class = mocker.patch("GitHubMCP.Client")
        mock_client_instance = AsyncMock()
        mock_client_class.return_value = mock_client_instance
        mock_client_instance.test_connection.return_value = "Connection successful"

        # Set up test data
        mock_params.return_value = {
            "token": {"password": "test-token"},
            "enabled_toolsets": "toolset1,toolset2",
            "readonly": "true",
        }
        mock_args.return_value = {}
        mock_command.return_value = "test-module"
        mock_arg_to_list.return_value = ["toolset1", "toolset2"]
        mock_arg_to_boolean.return_value = True

        # Execute
        await main()

        # Verify
        mock_client_class.assert_called_once()
        mock_client_instance.test_connection.assert_called_once()
        mock_return_results.assert_called_once_with("Connection successful")

    @pytest.mark.asyncio
    async def test_main_list_tools_success(self, mocker: MockerFixture):
        """
        Given: A list-tools command with valid parameters.
        When: The main function is called with list-tools command.
        Then: The client list_tools method is called and tools are returned successfully.
        """

        # Mock demisto functions
        mock_params = mocker.patch("GitHubMCP.demisto.params")
        mock_args = mocker.patch("GitHubMCP.demisto.args")
        mock_command = mocker.patch("GitHubMCP.demisto.command")
        mocker.patch("GitHubMCP.demisto.debug")
        mock_return_results = mocker.patch("GitHubMCP.return_results")
        mock_arg_to_list = mocker.patch("GitHubMCP.argToList")
        mock_arg_to_boolean = mocker.patch("GitHubMCP.argToBoolean")

        # Mock Client class
        mock_client_class = mocker.patch("GitHubMCP.Client")
        mock_client_instance = AsyncMock()
        mock_client_class.return_value = mock_client_instance
        mock_client_instance.list_tools.return_value = {"tools": ["tool1", "tool2"]}

        # Set up test data
        mock_params.return_value = {"token": {"password": "test-token"}, "enabled_toolsets": "toolset1", "readonly": "false"}
        mock_args.return_value = {}
        mock_command.return_value = "list-tools"
        mock_arg_to_list.return_value = ["toolset1"]
        mock_arg_to_boolean.return_value = False

        # Execute
        await main()

        # Verify
        mock_client_instance.list_tools.assert_called_once()
        mock_return_results.assert_called_once_with({"tools": ["tool1", "tool2"]})

    @pytest.mark.asyncio
    async def test_main_call_tool_with_arguments(self, mocker: MockerFixture):
        """
        Given: A call-tool command with tool name and arguments provided.
        When: The main function is called with call-tool command.
        Then: The client call_tool method is called with the correct parameters and result is returned.
        """

        # Mock demisto functions
        mock_params = mocker.patch("GitHubMCP.demisto.params")
        mock_args = mocker.patch("GitHubMCP.demisto.args")
        mock_command = mocker.patch("GitHubMCP.demisto.command")
        mocker.patch("GitHubMCP.demisto.debug")
        mock_return_results = mocker.patch("GitHubMCP.return_results")
        mock_arg_to_list = mocker.patch("GitHubMCP.argToList")
        mock_arg_to_boolean = mocker.patch("GitHubMCP.argToBoolean")

        # Mock Client class
        mock_client_class = mocker.patch("GitHubMCP.Client")
        mock_client_instance = AsyncMock()
        mock_client_class.return_value = mock_client_instance
        mock_client_instance.call_tool.return_value = {"result": "tool executed"}

        # Set up test data
        mock_params.return_value = {"token": {"password": "test-token"}, "enabled_toolsets": "", "readonly": "false"}
        mock_args.return_value = {"name": "test-tool", "arguments": '{"param1": "value1"}'}
        mock_command.return_value = "call-tool"
        mock_arg_to_list.return_value = []
        mock_arg_to_boolean.return_value = False

        # Execute
        await main()

        # Verify
        mock_client_instance.call_tool.assert_called_once_with("test-tool", '{"param1": "value1"}')
        mock_return_results.assert_called_once_with({"result": "tool executed"})

    @pytest.mark.asyncio
    async def test_main_call_tool_without_arguments(self, mocker: MockerFixture):
        """
        Given: A call-tool command with tool name but no arguments provided.
        When: The main function is called with call-tool command.
        Then: The client call_tool method is called with empty arguments and result is returned.
        """

        # Mock demisto functions
        mock_params = mocker.patch("GitHubMCP.demisto.params")
        mock_args = mocker.patch("GitHubMCP.demisto.args")
        mock_command = mocker.patch("GitHubMCP.demisto.command")
        mocker.patch("GitHubMCP.demisto.debug")
        mocker.patch("GitHubMCP.return_results")
        mock_arg_to_list = mocker.patch("GitHubMCP.argToList")
        mock_arg_to_boolean = mocker.patch("GitHubMCP.argToBoolean")

        # Mock Client class
        mock_client_class = mocker.patch("GitHubMCP.Client")
        mock_client_instance = AsyncMock()
        mock_client_class.return_value = mock_client_instance
        mock_client_instance.call_tool.return_value = {"result": "tool executed"}

        # Set up test data
        mock_params.return_value = {"token": {"password": "test-token"}, "enabled_toolsets": "", "readonly": "false"}
        mock_args.return_value = {"name": "test-tool"}
        mock_command.return_value = "call-tool"
        mock_arg_to_list.return_value = []
        mock_arg_to_boolean.return_value = False

        # Execute
        await main()

        # Verify
        mock_client_instance.call_tool.assert_called_once_with("test-tool", "")

    @pytest.mark.asyncio
    async def test_main_unknown_command(self, mocker: MockerFixture):
        """
        Given: An unknown command that is not implemented.
        When: The main function is called with the unknown command.
        Then: A NotImplementedError is raised and return_error is called with appropriate message.
        """

        # Mock demisto functions
        mock_params = mocker.patch("GitHubMCP.demisto.params")
        mock_args = mocker.patch("GitHubMCP.demisto.args")
        mock_command = mocker.patch("GitHubMCP.demisto.command")
        mocker.patch("GitHubMCP.demisto.debug")
        mock_return_error = mocker.patch("GitHubMCP.return_error")
        mock_arg_to_list = mocker.patch("GitHubMCP.argToList")
        mock_arg_to_boolean = mocker.patch("GitHubMCP.argToBoolean")

        # Mock Client class
        mock_client_class = mocker.patch("GitHubMCP.Client")
        mock_client_instance = AsyncMock()
        mock_client_class.return_value = mock_client_instance

        # Mock extract_root_error_message
        mock_extract_error = mocker.patch("GitHubMCP.extract_root_error_message")
        mock_extract_error.return_value = "Command unknown-command is not implemented"

        # Set up test data
        mock_params.return_value = {"token": {"password": "test-token"}, "enabled_toolsets": "", "readonly": "false"}
        mock_args.return_value = {}
        mock_command.return_value = "unknown-command"
        mock_arg_to_list.return_value = []
        mock_arg_to_boolean.return_value = False

        # Execute
        await main()

        # Verify
        mock_return_error.assert_called_once_with(
            "Failed to execute unknown-command command.\nError:\nCommand unknown-command is not implemented"
        )

    @pytest.mark.asyncio
    async def test_main_client_exception(self, mocker: MockerFixture):
        """
        Given: A test-module command where the client raises an exception.
        When: The main function is called and client test_connection fails.
        Then: The exception is caught and return_error is called with formatted error message.
        """

        # Mock demisto functions
        mock_params = mocker.patch("GitHubMCP.demisto.params")
        mock_args = mocker.patch("GitHubMCP.demisto.args")
        mock_command = mocker.patch("GitHubMCP.demisto.command")
        mocker.patch("GitHubMCP.demisto.debug")
        mock_return_error = mocker.patch("GitHubMCP.return_error")
        mock_arg_to_list = mocker.patch("GitHubMCP.argToList")
        mock_arg_to_boolean = mocker.patch("GitHubMCP.argToBoolean")

        # Mock Client class
        mock_client_class = mocker.patch("GitHubMCP.Client")
        mock_client_instance = AsyncMock()
        mock_client_class.return_value = mock_client_instance
        mock_client_instance.test_connection.side_effect = Exception("Connection failed")

        # Mock extract_root_error_message
        mock_extract_error = mocker.patch("GitHubMCP.extract_root_error_message")
        mock_extract_error.return_value = "Connection failed"

        # Set up test data
        mock_params.return_value = {"token": {"password": "test-token"}, "enabled_toolsets": "", "readonly": "false"}
        mock_args.return_value = {}
        mock_command.return_value = "test-module"
        mock_arg_to_list.return_value = []
        mock_arg_to_boolean.return_value = False

        # Execute
        await main()

        # Verify
        mock_return_error.assert_called_once_with("Failed to execute test-module command.\nError:\nConnection failed")
