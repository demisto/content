import traceback
from mcp.types import CallToolResult, TextContent
import sys

if sys.version_info < (3, 11):  # noqa: UP036
    # ExceptionGroup is new in Python 3.11, so we define it for older versions for testing purposes
    class ExceptionGroup(Exception):
        def __init__(self, message, exceptions):
            super().__init__(message)
            self.exceptions = exceptions

    class BaseExceptionGroup(BaseException):
        def __init__(self, message, exceptions):
            super().__init__(message)
            self.exceptions = exceptions


from GitHubMCP import (
    Client,
    extract_root_error_message,
    object_to_dict_recursive,
    get_text_from_call_result,
    list_tools,
    call_tool,
    BASE_URL,
)

import pytest
from pytest_mock import MockerFixture
from unittest.mock import AsyncMock
from CommonServerPython import EntryType, DemistoException


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


def test_object_to_dict_recursive_with_nested_objects():
    """
    Given: A custom object containing another custom object as an attribute.
    When: object_to_dict_recursive is called with the parent object.
    Then: Both objects should be recursively converted to nested dictionaries.
    """

    class InnerObject:
        def __init__(self):
            self.inner_value = "nested"

    class OuterObject:
        def __init__(self):
            self.outer_value = "parent"
            self.inner = InnerObject()

    obj = OuterObject()
    result = object_to_dict_recursive(obj)

    expected = {"outer_value": "parent", "inner": {"inner_value": "nested"}}
    assert result == expected


def test_object_to_dict_recursive_with_iterables():
    """
    Given: A list containing various types including tuples, sets, and custom objects.
    When: object_to_dict_recursive is called with the list.
    Then: All iterable items should be converted to lists with nested objects as dictionaries.
    """

    class TestObject:
        def __init__(self, value):
            self.value = value

    input_list = [TestObject("test1"), (TestObject("test2"), "string"), {"key", "set_item"}]

    result = object_to_dict_recursive(input_list)

    assert len(result) == 3
    assert list(result)[0] == {"value": "test1"}
    assert list(result)[1] == [{"value": "test2"}, "string"]
    assert set(list(result)[2]) == {"key", "set_item"}  # Set order may vary


def test_object_to_dict_recursive_with_dictionary():
    """
    Given: A dictionary containing nested dictionaries and custom objects as values.
    When: object_to_dict_recursive is called with the dictionary.
    Then: All nested values should be recursively converted while preserving the dictionary structure.
    """

    class TestObject:
        def __init__(self, value):
            self.value = value

    input_dict = {"simple": "string", "nested": {"inner": TestObject("nested_value")}, "object": TestObject("direct_value")}

    result = object_to_dict_recursive(input_dict)

    expected = {"simple": "string", "nested": {"inner": {"value": "nested_value"}}, "object": {"value": "direct_value"}}
    assert result == expected


def test_object_to_dict_recursive_with_primitives():
    """
    Given: Primitive data types including strings, integers, booleans, and None.
    When: object_to_dict_recursive is called with each primitive type.
    Then: The primitive values should be returned unchanged.
    """
    primitives = ["string", 42, True, False, None, 3.14]

    for primitive in primitives:
        result = object_to_dict_recursive(primitive)
        assert result == primitive


def test_get_text_from_call_result_with_text_content():
    """
    Given: A CallToolResult with content containing a TextContent object with text.
    When: get_text_from_call_result is called with the result.
    Then: The text from the TextContent object should be returned.
    """
    text_content = TextContent(type="text", text="Hello, world!")
    call_result = CallToolResult(content=[text_content], isError=False)

    result = get_text_from_call_result(call_result)

    assert result == "Hello, world!"


def test_get_text_from_call_result_with_empty_content():
    """
    Given: A CallToolResult with empty or None content.
    When: get_text_from_call_result is called with the result.
    Then: An empty string should be returned.
    """
    call_result = CallToolResult(content=[], isError=False)

    result = get_text_from_call_result(call_result)

    assert result == ""


def test_get_text_from_call_result_with_none_content():
    """
    Given: A CallToolResult with content set to None.
    When: get_text_from_call_result is called with the result.
    Then: An empty string should be returned.
    """
    call_result = CallToolResult(content=[], isError=False)

    result = get_text_from_call_result(call_result)

    assert result == ""


@pytest.mark.asyncio
async def test_get_session_successful_initialization(mocker: MockerFixture):
    """
    Given: A Client instance with valid configuration and mocked MCP components.
    When: The _get_session context manager is used successfully.
    Then: A session should be initialized and yielded with proper cleanup.
    """
    # Mock the session
    mock_session = mocker.AsyncMock()
    mock_session.initialize = mocker.AsyncMock()

    # Mock the streams
    mock_read_stream = mocker.AsyncMock()
    mock_write_stream = mocker.AsyncMock()
    mock_transport = mocker.AsyncMock()

    # Mock streamablehttp_client context manager
    mock_streamable_client = mocker.patch("GitHubMCP.streamablehttp_client")
    mock_streamable_client.return_value.__aenter__ = mocker.AsyncMock(
        return_value=(mock_read_stream, mock_write_stream, mock_transport)
    )
    mock_streamable_client.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

    # Mock ClientSession context manager
    mock_client_session = mocker.patch("GitHubMCP.ClientSession")
    mock_client_session.return_value = mock_session
    mock_client_session.return_value.__aenter__ = mocker.AsyncMock(return_value=mock_session)
    mock_client_session.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

    # Create client
    client = Client(
        base_url="https://api.githubcopilot.com/mcp/",
        token="test_token",
        toolsets=["context", "repos"],
        readonly=True,
    )

    # Test the context manager
    async with client._get_session() as session:
        assert session == mock_session

    # Verify session.initialize was called
    mock_session.initialize.assert_called_once()

    # Verify streamablehttp_client was called with correct parameters
    mock_streamable_client.assert_called_once_with("https://api.githubcopilot.com/mcp/", headers=client.headers)


@pytest.mark.asyncio
async def test_get_session_initialization_failure(mocker: MockerFixture):
    """
    Given: A Client instance where session initialization fails with an exception.
    When: The _get_session context manager is used and initialization raises an error.
    Then: The exception should propagate while still performing proper cleanup.
    """
    # Mock session that fails during initialization
    mock_session = mocker.AsyncMock()
    mock_session.initialize.side_effect = RuntimeError("Session initialization failed")

    # Mock the streams
    mock_read_stream = mocker.AsyncMock()
    mock_write_stream = mocker.AsyncMock()
    mock_transport = mocker.AsyncMock()

    # Mock streamablehttp_client context manager
    mock_streamable_client = mocker.patch("GitHubMCP.streamablehttp_client")
    mock_streamable_client.return_value.__aenter__ = mocker.AsyncMock(
        return_value=(mock_read_stream, mock_write_stream, mock_transport)
    )
    mock_streamable_client.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

    # Mock ClientSession context manager
    mock_client_session = mocker.patch("GitHubMCP.ClientSession")
    mock_client_session.return_value = mock_session
    mock_client_session.return_value.__aenter__ = mocker.AsyncMock(return_value=mock_session)
    mock_client_session.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

    # Create client
    client = Client(
        base_url="https://api.githubcopilot.com/mcp/",
        token="test_token",
        toolsets=["context"],
        readonly=False,
    )

    # Test that the exception is properly raised
    with pytest.raises(RuntimeError, match="Session initialization failed"):
        async with client._get_session():
            pass

    # Verify initialization was attempted
    mock_session.initialize.assert_called_once()


@pytest.mark.asyncio
async def test_get_session_with_custom_headers(mocker: MockerFixture):
    """
    Given: A Client instance with custom toolsets and readonly configuration.
    When: The _get_session context manager creates the streamable HTTP connection.
    Then: The headers should include the correct authorization, toolsets, and readonly values.
    """
    # Mock the session and streams
    mock_session = mocker.AsyncMock()
    mock_session.initialize = mocker.AsyncMock()
    mock_read_stream = mocker.AsyncMock()
    mock_write_stream = mocker.AsyncMock()
    mock_transport = mocker.AsyncMock()

    # Mock streamablehttp_client context manager
    mock_streamable_client = mocker.patch("GitHubMCP.streamablehttp_client")
    mock_streamable_client.return_value.__aenter__ = mocker.AsyncMock(
        return_value=(mock_read_stream, mock_write_stream, mock_transport)
    )
    mock_streamable_client.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

    # Mock ClientSession context manager
    mock_client_session = mocker.patch("GitHubMCP.ClientSession")
    mock_client_session.return_value = mock_session
    mock_client_session.return_value.__aenter__ = mocker.AsyncMock(return_value=mock_session)
    mock_client_session.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

    # Create client with specific configuration
    client = Client(
        base_url="https://api.githubcopilot.com/mcp/",
        token="secret_token",
        toolsets=["repos", "issues", "pull_requests"],
        readonly=False,
    )

    # Test the context manager
    async with client._get_session():
        pass

    # Verify the headers were constructed correctly
    expected_headers = {
        "Authorization": "Bearer secret_token",
        "X-MCP-Toolsets": "repos,issues,pull_requests",
        "X-MCP-Readonly": "false",
    }

    # Verify streamablehttp_client was called with the expected headers
    mock_streamable_client.assert_called_once_with("https://api.githubcopilot.com/mcp/", headers=expected_headers)


@pytest.mark.asyncio
async def test_test_connection_success(mocker: MockerFixture):
    """
    Given: A Client instance with valid configuration and a mock session that initializes successfully.
    When: test_connection is called and the session context manager completes without errors.
    Then: The method should return "ok" indicating successful connection.
    """
    mock_session = AsyncMock()
    mock_get_session = mocker.patch.object(Client, "_get_session")
    mock_get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
    mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

    client = Client(BASE_URL, token="123", toolsets=["context"], readonly=True)

    result = await client.test_connection()

    assert result == "ok"
    mock_get_session.assert_called_once()


@pytest.mark.asyncio
async def test_test_connection_failure(mocker: MockerFixture):
    """
    Given: A Client instance with configuration that causes session initialization to fail.
    When: test_connection is called and the session context manager raises an exception.
    Then: The exception should propagate from the test_connection method.
    """
    mock_get_session = mocker.patch.object(Client, "_get_session")
    mock_get_session.return_value.__aenter__ = AsyncMock(side_effect=ConnectionError("Failed to connect to MCP server"))
    mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)

    client = Client(BASE_URL, token="123", toolsets=["context"], readonly=True)

    with pytest.raises(ConnectionError, match="Failed to connect to MCP server"):
        await client.test_connection()

    mock_get_session.assert_called_once()


@pytest.mark.asyncio
async def test_list_tools_success(mocker: MockerFixture):
    """
    Given: A Client instance and a mock tools response with multiple available tools.
    When: list_tools is called and the client returns a successful tools list.
    Then: The function should return formatted CommandResults with tool names and recursive dictionary outputs.
    """
    # Create mock tools objects
    mock_tool1 = mocker.Mock()
    mock_tool1.name = "search-hosts"
    mock_tool1.description = "Search for hosts in CrowdStrike"

    mock_tool2 = mocker.Mock()
    mock_tool2.name = "get-detections"
    mock_tool2.description = "Retrieve detection data"

    # Create mock tools response
    mock_tools_response = mocker.Mock()
    mock_tools_response.tools = [mock_tool1, mock_tool2]

    # Create mock client
    mock_client = mocker.Mock()
    mock_client.list_tools = AsyncMock(return_value=mock_tools_response)

    # Mock object_to_dict_recursive
    mock_dict_conversion = mocker.patch("GitHubMCP.object_to_dict_recursive")
    mock_dict_conversion.return_value = [
        {"name": "search-hosts", "description": "Search for hosts in CrowdStrike"},
        {"name": "get-detections", "description": "Retrieve detection data"},
    ]

    result = await list_tools(mock_client)

    assert result.readable_output == "Available 2 tools:\n['search-hosts', 'get-detections']"
    assert result.outputs_prefix == "ListTools.Tools"
    mock_client.list_tools.assert_called_once()
    mock_dict_conversion.assert_called_once_with([mock_tool1, mock_tool2])


@pytest.mark.asyncio
async def test_list_tools_empty_response(mocker: MockerFixture):
    """
    Given: A Client instance and a mock tools response with no available tools.
    When: list_tools is called and the client returns an empty tools list.
    Then: The function should return CommandResults indicating zero available tools.
    """
    # Create mock empty tools response
    mock_tools_response = mocker.Mock()
    mock_tools_response.tools = []

    # Create mock client
    mock_client = mocker.Mock()
    mock_client.list_tools = AsyncMock(return_value=mock_tools_response)

    # Mock object_to_dict_recursive
    mock_dict_conversion = mocker.patch("GitHubMCP.object_to_dict_recursive")
    mock_dict_conversion.return_value = []

    result = await list_tools(mock_client)

    assert result.readable_output == "Available 0 tools:\n[]"
    assert result.outputs_prefix == "ListTools.Tools"
    assert result.outputs == []
    mock_client.list_tools.assert_called_once()


@pytest.mark.asyncio
async def test_list_tools_client_exception(mocker: MockerFixture):
    """
    Given: A Client instance that raises an exception when listing tools.
    When: list_tools is called and the client.list_tools method fails.
    Then: The exception should propagate from the list_tools function.
    """
    # Create mock client that raises exception
    mock_client = mocker.Mock()
    mock_client.list_tools = AsyncMock(side_effect=ConnectionError("Failed to connect to MCP server"))

    with pytest.raises(ConnectionError, match="Failed to connect to MCP server"):
        await list_tools(mock_client)

    mock_client.list_tools.assert_called_once()


@pytest.mark.asyncio
async def test_call_tool_success_with_json_response(mocker: MockerFixture):
    """
    Given: A Client instance with a tool that returns valid JSON content in the response.
    When: call_tool is called with valid tool name and JSON arguments.
    Then: The function should return CommandResults with a markdown table and NOTE entry type.
    """
    # Mock successful call result with JSON content
    mock_text_content = TextContent(type="text", text='{"status": "success", "count": 5}')
    mock_call_result = CallToolResult(content=[mock_text_content], isError=False)

    # Create mock client
    mock_client = mocker.Mock()
    mock_client.call_tool = AsyncMock(return_value=mock_call_result)

    # Mock object_to_dict_recursive
    mock_dict_conversion = mocker.patch("GitHubMCP.object_to_dict_recursive")
    mock_dict_conversion.return_value = {"content": [{"text": '{"status": "success", "count": 5}'}], "isError": False}

    # Mock tableToMarkdown
    mock_table = mocker.patch("GitHubMCP.tableToMarkdown")
    mock_table.return_value = "| status | count |\n|--------|-------|\n| success | 5 |"

    result = await call_tool(mock_client, "search-hosts", '{"limit": 10}')

    assert "| status | count |" in result.readable_output
    assert result.outputs_prefix == "CallTool.Tool"
    assert result.entry_type == EntryType.NOTE
    mock_client.call_tool.assert_called_once_with("search-hosts", {"limit": 10})


@pytest.mark.asyncio
async def test_call_tool_success_with_text_response(mocker: MockerFixture):
    """
    Given: A Client instance with a tool that returns plain text content in the response.
    When: call_tool is called and the response text is not valid JSON.
    Then: The function should return CommandResults with plain text readable output and NOTE entry type.
    """
    # Mock successful call result with plain text content
    mock_text_content = TextContent(type="text", text="Operation completed successfully")
    mock_call_result = CallToolResult(content=[mock_text_content], isError=False)

    # Create mock client
    mock_client = mocker.Mock()
    mock_client.call_tool = AsyncMock(return_value=mock_call_result)

    # Mock object_to_dict_recursive
    mock_dict_conversion = mocker.patch("GitHubMCP.object_to_dict_recursive")
    mock_dict_conversion.return_value = {"content": [{"text": "Operation completed successfully"}], "isError": False}

    result = await call_tool(mock_client, "update-host", '{"host_id": "123"}')

    assert result.readable_output == "Tool Execution 'update-host': Operation completed successfully"
    assert result.outputs_prefix == "CallTool.Tool"
    assert result.entry_type == EntryType.NOTE


@pytest.mark.asyncio
async def test_call_tool_error_response(mocker: MockerFixture):
    """
    Given: A Client instance with a tool that returns an error response with isError set to True.
    When: call_tool is called and the tool execution fails on the server side.
    Then: The function should return CommandResults with error message and ERROR entry type.
    """
    # Mock error call result
    mock_text_content = TextContent(type="text", text="Host not found with ID 999")
    mock_call_result = CallToolResult(content=[mock_text_content], isError=True)

    # Create mock client
    mock_client = mocker.Mock()
    mock_client.call_tool = AsyncMock(return_value=mock_call_result)

    # Mock object_to_dict_recursive
    mock_dict_conversion = mocker.patch("GitHubMCP.object_to_dict_recursive")
    mock_dict_conversion.return_value = {"content": [{"text": "Host not found with ID 999"}], "isError": True}

    result = await call_tool(mock_client, "get-host", '{"host_id": "999"}')

    assert result.readable_output == "Tool execution 'get-host' failed: Host not found with ID 999."
    assert result.outputs_prefix == "CallTool.Tool"
    assert result.entry_type == EntryType.ERROR


@pytest.mark.asyncio
async def test_call_tool_invalid_json_arguments(mocker: MockerFixture):
    """
    Given: A Client instance and invalid JSON string provided as arguments parameter.
    When: call_tool is called with malformed JSON arguments that cannot be parsed.
    Then: The function should raise a DemistoException with details about the invalid JSON.
    """
    mock_client = mocker.Mock()

    with pytest.raises(DemistoException, match="Invalid JSON provided for arguments"):
        await call_tool(mock_client, "search-hosts", '{"invalid": json}')

    # Verify client.call_tool was never called due to JSON parsing failure
    mock_client.call_tool.assert_not_called()
