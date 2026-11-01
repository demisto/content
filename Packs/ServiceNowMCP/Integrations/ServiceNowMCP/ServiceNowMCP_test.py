import pytest
from pytest_mock import MockerFixture

import demistomock as demisto
from ServiceNowMCP import main, build_servicenow_urls, validate_required_params, DEFAULT_MCP_SERVER_NAME


VALID_PARAMS = {
    "instance_url": "https://dev12345.service-now.com",
    "server_name": "sn_mcp_server_default",
    "oauth_credentials": {"identifier": "test_client_id", "password": "test_client_secret"},
    "auth_code": {"password": "test_auth_code"},
    "redirect_uri": "https://oproxy.demisto.ninja/authcode",
    "insecure": False,
}


class TestBuildServiceNowUrls:
    """Unit tests for build_servicenow_urls."""

    def test_build_urls_with_explicit_server_name(self):
        """Given: A full ServiceNow instance URL and explicit server name.
        When: build_servicenow_urls is called.
        Then: Correct base_url, authorization_endpoint, and token_endpoint are returned.
        """
        base_url, auth_endpoint, token_endpoint = build_servicenow_urls("https://dev12345.service-now.com", "my_server")

        assert base_url == "https://dev12345.service-now.com/sncapps/mcp-server/mcp/my_server"
        assert auth_endpoint == "https://dev12345.service-now.com/oauth_auth.do"
        assert token_endpoint == "https://dev12345.service-now.com/oauth_token.do"

    def test_build_urls_with_empty_server_name_uses_default(self):
        """Given: A full ServiceNow instance URL and an empty server name.
        When: build_servicenow_urls is called.
        Then: The default Quickstart server name is used in the base URL.
        """
        base_url, _, _ = build_servicenow_urls("https://dev12345.service-now.com", "")

        assert base_url == f"https://dev12345.service-now.com/sncapps/mcp-server/mcp/{DEFAULT_MCP_SERVER_NAME}"

    def test_build_urls_strips_whitespace_and_trailing_slash(self):
        """Given: An instance URL with surrounding whitespace and a trailing slash.
        When: build_servicenow_urls is called.
        Then: The URLs are built with the cleaned instance URL.
        """
        base_url, auth_endpoint, token_endpoint = build_servicenow_urls(
            "  https://dev12345.service-now.com/  ", "  custom_server  "
        )

        assert base_url == "https://dev12345.service-now.com/sncapps/mcp-server/mcp/custom_server"
        assert auth_endpoint == "https://dev12345.service-now.com/oauth_auth.do"
        assert token_endpoint == "https://dev12345.service-now.com/oauth_token.do"


class TestValidateRequiredParams:
    """Unit tests for validate_required_params."""

    def test_valid_params_passes(self):
        """Given: All required parameters are provided.
        When: validate_required_params is called.
        Then: No exception is raised.
        """
        validate_required_params("https://dev12345.service-now.com", "cid", "csecret")

    def test_missing_instance_raises(self):
        """Given: The instance URL is missing.
        When: validate_required_params is called.
        Then: A ValueError is raised mentioning the instance requirement.
        """
        with pytest.raises(ValueError, match="ServiceNow Instance URL"):
            validate_required_params("", "cid", "csecret")

    def test_missing_client_id_raises(self):
        """Given: The Client ID is missing.
        When: validate_required_params is called.
        Then: A ValueError is raised mentioning OAuth credentials.
        """
        with pytest.raises(ValueError, match="Client ID and Client Secret"):
            validate_required_params("https://dev12345.service-now.com", "", "csecret")

    def test_missing_client_secret_raises(self):
        """Given: The Client Secret is missing.
        When: validate_required_params is called.
        Then: A ValueError is raised mentioning OAuth credentials.
        """
        with pytest.raises(ValueError, match="Client ID and Client Secret"):
            validate_required_params("https://dev12345.service-now.com", "cid", "")


class TestMain:
    """Unit tests for the main function of ServiceNowMCP."""

    @pytest.mark.asyncio
    async def test_test_module_command(self, mocker: MockerFixture):
        """Given: The test-module command is called for an OAuth integration.
        When: Main function processes the command.
        Then: return_error is called with a message directing the user to the auth-test command.
        """

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.close = mock_close
        mocker.patch("ServiceNowMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="test-module")
        mock_return_error = mocker.patch("ServiceNowMCP.return_error")

        await main()

        mock_return_error.assert_called_once()
        error_call = mock_return_error.call_args[0][0]
        assert "Test module is unavailable for this integration" in error_call
        assert "servicenow-mcp-auth-test" in error_call

    @pytest.mark.asyncio
    async def test_list_tools_command(self, mocker: MockerFixture):
        """Given: The list-tools command is called with valid params.
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
        mocker.patch("ServiceNowMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="list-tools")
        mock_return_results = mocker.patch("ServiceNowMCP.return_results")

        await main()

        mock_return_results.assert_called_once_with({"tools": []})

    @pytest.mark.asyncio
    async def test_call_tool_command_with_arguments(self, mocker: MockerFixture):
        """Given: The call-tool command is called with a tool name and arguments.
        When: Main function processes the command.
        Then: The client's call_tool method is called with the provided parameters.
        """

        captured: dict = {}

        async def mock_call_tool(name, arguments):
            captured["name"] = name
            captured["arguments"] = arguments
            return {"result": "success"}

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.call_tool = mock_call_tool
        mock_client.close = mock_close
        mocker.patch("ServiceNowMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
        mocker.patch.object(demisto, "args", return_value={"name": "lookup_incident", "arguments": '{"number": "INC0010001"}'})
        mocker.patch.object(demisto, "command", return_value="call-tool")
        mock_return_results = mocker.patch("ServiceNowMCP.return_results")

        await main()

        assert captured == {"name": "lookup_incident", "arguments": '{"number": "INC0010001"}'}
        mock_return_results.assert_called_once_with({"result": "success"})

    @pytest.mark.asyncio
    async def test_call_tool_command_without_arguments(self, mocker: MockerFixture):
        """Given: The call-tool command is called with only a tool name (no arguments).
        When: Main function processes the command.
        Then: The client's call_tool method is called with an empty arguments string.
        """

        captured: dict = {}

        async def mock_call_tool(name, arguments):
            captured["name"] = name
            captured["arguments"] = arguments
            return {"result": "ok"}

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.call_tool = mock_call_tool
        mock_client.close = mock_close
        mocker.patch("ServiceNowMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
        mocker.patch.object(demisto, "args", return_value={"name": "list_incidents"})
        mocker.patch.object(demisto, "command", return_value="call-tool")
        mock_return_results = mocker.patch("ServiceNowMCP.return_results")

        await main()

        assert captured == {"name": "list_incidents", "arguments": ""}
        mock_return_results.assert_called_once_with({"result": "ok"})

    @pytest.mark.asyncio
    async def test_auth_test_command(self, mocker: MockerFixture):
        """Given: The servicenow-mcp-auth-test command is called.
        When: Main function processes the command.
        Then: The client's test_connection method is called with auth_test=True.
        """

        captured: dict = {}

        async def mock_test_connection(auth_test=False):
            captured["auth_test"] = auth_test
            return {"status": "authenticated"}

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.test_connection = mock_test_connection
        mock_client.close = mock_close
        mocker.patch("ServiceNowMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="servicenow-mcp-auth-test")
        mock_return_results = mocker.patch("ServiceNowMCP.return_results")

        await main()

        assert captured == {"auth_test": True}
        mock_return_results.assert_called_once_with({"status": "authenticated"})

    @pytest.mark.asyncio
    async def test_generate_login_url_command(self, mocker: MockerFixture):
        """Given: The servicenow-mcp-generate-login-url command is called.
        When: Main function processes the command.
        Then: generate_login_url is called with the ServiceNow authorization endpoint and troubleshooting enabled.
        """

        captured_kwargs: dict = {}

        async def mock_generate_login_url(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return {"login_url": "https://dev12345.service-now.com/oauth_auth.do?..."}

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.close = mock_close
        mocker.patch("ServiceNowMCP.Client", return_value=mock_client)
        mocker.patch("ServiceNowMCP.generate_login_url", side_effect=mock_generate_login_url)
        mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="servicenow-mcp-generate-login-url")
        mock_return_results = mocker.patch("ServiceNowMCP.return_results")

        await main()

        assert captured_kwargs["authorization_endpoint"] == "https://dev12345.service-now.com/oauth_auth.do"
        assert captured_kwargs["redirect_uri"] == VALID_PARAMS["redirect_uri"]
        assert captured_kwargs["troubleshooting_redirect"] is True
        mock_return_results.assert_called_once_with({"login_url": "https://dev12345.service-now.com/oauth_auth.do?..."})

    @pytest.mark.asyncio
    async def test_unknown_command(self, mocker: MockerFixture):
        """Given: An unknown command is called.
        When: Main function processes the command.
        Then: A NotImplementedError is raised and return_error is called.
        """

        async def mock_close():
            pass

        mock_client = mocker.MagicMock()
        mock_client.close = mock_close
        mocker.patch("ServiceNowMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="unknown-command")
        mock_return_error = mocker.patch("ServiceNowMCP.return_error")

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
        mocker.patch("ServiceNowMCP.Client", return_value=mock_client)
        mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="list-tools")
        mock_return_error = mocker.patch("ServiceNowMCP.return_error")

        await main()

        mock_return_error.assert_called_once()
        error_call = mock_return_error.call_args[0][0]
        assert "Failed to execute list-tools command" in error_call
        assert "Connection failed" in error_call

    @pytest.mark.asyncio
    async def test_validation_failure_missing_instance(self, mocker: MockerFixture):
        """Given: The integration is configured without a ServiceNow instance.
        When: Main function processes any command.
        Then: validate_required_params raises ValueError and return_error is called.
        """
        params = dict(VALID_PARAMS)
        params["instance_url"] = ""

        mocker.patch.object(demisto, "params", return_value=params)
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="list-tools")
        mock_return_error = mocker.patch("ServiceNowMCP.return_error")

        await main()

        mock_return_error.assert_called_once()
        error_call = mock_return_error.call_args[0][0]
        assert "ServiceNow Instance" in error_call

    @pytest.mark.asyncio
    async def test_validation_failure_missing_oauth_credentials(self, mocker: MockerFixture):
        """Given: The integration is configured without OAuth credentials.
        When: Main function processes any command.
        Then: validate_required_params raises ValueError and return_error is called.
        """
        params = dict(VALID_PARAMS)
        params["oauth_credentials"] = {"identifier": "", "password": ""}

        mocker.patch.object(demisto, "params", return_value=params)
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="list-tools")
        mock_return_error = mocker.patch("ServiceNowMCP.return_error")

        await main()

        mock_return_error.assert_called_once()
        error_call = mock_return_error.call_args[0][0]
        assert "Client ID and Client Secret" in error_call
