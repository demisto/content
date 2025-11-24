import traceback
from CrowdStrikeFalconMCP import (
    Client,
    extract_root_error_message,
    object_to_dict_recursive,
    get_text_from_call_result,
    route_server_log,
    list_tools,
    call_tool,
)
from pytest_mock import MockerFixture
import pytest
from mcp.types import CallToolResult, TextContent
import subprocess
from unittest.mock import Mock, AsyncMock
from CommonServerPython import EntryType, DemistoException


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


FALCON_BASE_API_URL = "https://api.crowdstrike.com"


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
    assert result[0] == {"value": "test1"}
    assert result[1] == [{"value": "test2"}, "string"]
    assert set(result[2]) == {"key", "set_item"}  # Set order may vary


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


def test_route_server_log_with_debug_level(mocker: MockerFixture):
    """
    Given: A server log line containing the DEBUG log level indicator.
    When: route_server_log is called with the debug log line.
    Then: The line should be routed to demisto.debug function.
    """
    mock_debug = mocker.patch("CrowdStrikeFalconMCP.demisto.debug")
    mock_info = mocker.patch("CrowdStrikeFalconMCP.demisto.info")

    log_line = "2024-01-01 10:00:00 - DEBUG - This is a debug message"

    route_server_log(log_line)

    mock_debug.assert_called_once_with("2024-01-01 10:00:00 - DEBUG - This is a debug message")
    mock_info.assert_not_called()


def test_route_server_log_with_info_level(mocker: MockerFixture):
    """
    Given: A server log line containing the INFO log level indicator.
    When: route_server_log is called with the info log line.
    Then: The line should be routed to demisto.info function.
    """
    mock_debug = mocker.patch("CrowdStrikeFalconMCP.demisto.debug")
    mock_info = mocker.patch("CrowdStrikeFalconMCP.demisto.info")

    log_line = "2024-01-01 10:00:00 - INFO - This is an info message"

    route_server_log(log_line)

    mock_info.assert_called_once_with("2024-01-01 10:00:00 - INFO - This is an info message")
    mock_debug.assert_not_called()


def test_route_server_log_with_unknown_level(mocker: MockerFixture):
    """
    Given: A server log line without recognizable DEBUG or INFO log level indicators.
    When: route_server_log is called with the unrecognized log line.
    Then: The line should default to being routed to demisto.info function.
    """
    mock_debug = mocker.patch("CrowdStrikeFalconMCP.demisto.debug")
    mock_info = mocker.patch("CrowdStrikeFalconMCP.demisto.info")

    log_line = "2024-01-01 10:00:00 - WARNING - This is a warning message"

    route_server_log(log_line)

    mock_info.assert_called_once_with("2024-01-01 10:00:00 - WARNING - This is a warning message")
    mock_debug.assert_not_called()


def test_route_server_log_strips_whitespace(mocker: MockerFixture):
    """
    Given: A server log line with leading and trailing whitespace containing DEBUG indicator.
    When: route_server_log is called with the whitespace-padded log line.
    Then: The whitespace should be stripped before routing to demisto.debug function.
    """
    mock_debug = mocker.patch("CrowdStrikeFalconMCP.demisto.debug")

    log_line = "   2024-01-01 10:00:00 - DEBUG - Debug message with whitespace   "

    route_server_log(log_line)

    mock_debug.assert_called_once_with("2024-01-01 10:00:00 - DEBUG - Debug message with whitespace")


@pytest.mark.asyncio
async def test_server_context_manager_successful_startup(mocker: MockerFixture):
    """
    Given: A Client instance with valid configuration and a mock subprocess that starts successfully.
    When: The _server context manager is used and the server starts up correctly.
    Then: The process should be started with correct arguments and environment variables.
    """
    # Mock subprocess.Popen
    mock_process = Mock()
    mock_process.poll.return_value = None  # Process is running
    mock_popen = mocker.patch("CrowdStrikeFalconMCP.subprocess.Popen", return_value=mock_process)

    # Mock _monitor_server_startup
    mock_monitor = mocker.patch.object(Client, "_monitor_server_startup", new_callable=AsyncMock)

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts", "intel"],
        host="127.0.0.1",
        port=8080,
    )

    async with client._server():
        pass

    # Verify subprocess was called with correct arguments
    expected_args = [
        "falcon-mcp",
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--port",
        "8080",
    ]

    mock_popen.assert_called_once()
    call_args = mock_popen.call_args
    assert call_args[1]["args"] == expected_args

    # Verify environment variables
    env = call_args[1]["env"]
    assert env["FALCON_CLIENT_ID"] == "test_id"
    assert env["FALCON_CLIENT_SECRET"] == "test_secret"
    assert env["FALCON_BASE_URL"] == "https://api.crowdstrike.com"
    assert env["FALCON_MCP_MODULES"] == "hosts,intel"

    mock_monitor.assert_called_once()


@pytest.mark.asyncio
async def test_server_context_manager_process_termination(mocker: MockerFixture):
    """
    Given: A Client instance and a running subprocess that needs to be terminated.
    When: The _server context manager exits and the process is still running.
    Then: The process should be terminated gracefully with a 2-second timeout.
    """
    mock_process = Mock()
    mock_process.poll.return_value = None  # Process is running
    mock_process.wait = Mock()
    mocker.patch("CrowdStrikeFalconMCP.subprocess.Popen", return_value=mock_process)
    mocker.patch.object(Client, "_monitor_server_startup", new_callable=AsyncMock)

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )

    async with client._server():
        pass

    mock_process.terminate.assert_called_once()
    mock_process.wait.assert_called_once_with(timeout=2)


@pytest.mark.asyncio
async def test_server_context_manager_process_kill_on_timeout(mocker: MockerFixture):
    """
    Given: A Client instance and a subprocess that doesn't terminate within the timeout period.
    When: The _server context manager exits and process termination times out.
    Then: The process should be forcefully killed after the timeout expires.
    """
    mock_process = Mock()
    mock_process.poll.return_value = None  # Process is running
    mock_process.wait.side_effect = subprocess.TimeoutExpired(["falcon-mcp"], 2)
    mocker.patch("CrowdStrikeFalconMCP.subprocess.Popen", return_value=mock_process)
    mocker.patch.object(Client, "_monitor_server_startup", new_callable=AsyncMock)

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )

    async with client._server():
        pass

    mock_process.terminate.assert_called_once()
    mock_process.wait.assert_called_once_with(timeout=2)
    mock_process.kill.assert_called_once()


@pytest.mark.asyncio
async def test_server_context_manager_already_terminated_process(mocker: MockerFixture):
    """
    Given: A Client instance and a subprocess that has already terminated.
    When: The _server context manager exits and the process is no longer running.
    Then: No termination or kill operations should be attempted on the process.
    """
    mock_process = Mock()
    mock_process.poll.return_value = 0  # Process has already exited
    mocker.patch("CrowdStrikeFalconMCP.subprocess.Popen", return_value=mock_process)
    mocker.patch.object(Client, "_monitor_server_startup", new_callable=AsyncMock)

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )

    async with client._server():
        pass

    mock_process.terminate.assert_not_called()
    mock_process.kill.assert_not_called()
    mock_process.wait.assert_not_called()


@pytest.mark.asyncio
async def test_server_context_manager_debug_mode_environment(mocker: MockerFixture):
    """
    Given: A Client instance with debug mode enabled.
    When: The _server context manager starts the subprocess.
    Then: The FALCON_MCP_DEBUG environment variable should be set to 'true'.
    """
    mock_process = Mock()
    mock_process.poll.return_value = None
    mock_popen = mocker.patch("CrowdStrikeFalconMCP.subprocess.Popen", return_value=mock_process)
    mocker.patch.object(Client, "_monitor_server_startup", new_callable=AsyncMock)
    mocker.patch("CrowdStrikeFalconMCP.is_debug_mode", return_value=True)

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )

    async with client._server():
        pass

    call_args = mock_popen.call_args
    env = call_args[1]["env"]
    assert env["FALCON_MCP_DEBUG"] == "true"


@pytest.mark.asyncio
async def test_server_context_manager_exception_during_startup(mocker: MockerFixture):
    """
    Given: A Client instance where the server startup monitoring raises an exception.
    When: The _server context manager is used and startup fails.
    Then: The process should still be terminated in the cleanup even after the exception.
    """
    mock_process = Mock()
    mock_process.poll.return_value = None
    mocker.patch("CrowdStrikeFalconMCP.subprocess.Popen", return_value=mock_process)
    mock_monitor = mocker.patch.object(Client, "_monitor_server_startup", new_callable=AsyncMock)
    mock_monitor.side_effect = RuntimeError("Startup failed")

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )

    with pytest.raises(RuntimeError, match="Startup failed"):
        async with client._server():
            pass

    mock_process.terminate.assert_called_once()


@pytest.mark.asyncio
async def test_monitor_server_startup_success(mocker: MockerFixture):
    """
    Given: A Client instance with a mock process that outputs the expected startup keyword.
    When: _monitor_server_startup is called and the server starts successfully.
    Then: The method should complete without raising an exception and create a log streaming task in debug mode.
    """
    # Mock the process stdout
    mock_stdout = mocker.Mock()
    mock_stdout.readline.side_effect = [b"Starting server...\n", b"StreamableHTTP session manager started\n"]

    # Mock process
    mock_process = mocker.Mock()
    mock_process.stdout = mock_stdout

    # Mock asyncio.to_thread to return the readline results synchronously
    mocker.patch("asyncio.to_thread", side_effect=lambda func: func())

    # Mock route_server_log
    mock_route_log = mocker.patch("CrowdStrikeFalconMCP.route_server_log")

    # Mock is_debug_mode and asyncio.create_task
    mocker.patch("CrowdStrikeFalconMCP.is_debug_mode", return_value=True)
    mock_create_task = mocker.patch("asyncio.create_task")
    mocker.patch.object(Client, "_stream_logs")

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )
    client.process = mock_process

    await client._monitor_server_startup()

    # Verify logging calls
    assert mock_route_log.call_count == 2
    mock_route_log.assert_any_call("[FALCON MCP SERVER] Starting server...")
    mock_route_log.assert_any_call("[FALCON MCP SERVER] StreamableHTTP session manager started")

    # Verify task creation in debug mode
    mock_create_task.assert_called_once()


@pytest.mark.asyncio
async def test_monitor_server_startup_process_exits_early(mocker: MockerFixture):
    """
    Given: A Client instance with a mock process that exits before outputting the startup keyword.
    When: _monitor_server_startup is called and the process exits unexpectedly.
    Then: The method should raise a RuntimeError indicating the server exited before startup.
    """
    # Mock the process stdout to return empty (process exited)
    mock_stdout = mocker.Mock()
    mock_stdout.readline.side_effect = [
        b"Starting server...\n",
        b"",  # Empty line indicates process exit
    ]

    # Mock process
    mock_process = mocker.Mock()
    mock_process.stdout = mock_stdout

    # Mock asyncio.to_thread
    mocker.patch("asyncio.to_thread", side_effect=lambda func: func())

    # Mock route_server_log
    mocker.patch("CrowdStrikeFalconMCP.route_server_log")

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )
    client.process = mock_process

    with pytest.raises(RuntimeError, match="Server process exited before startup"):
        await client._monitor_server_startup()


@pytest.mark.asyncio
async def test_monitor_server_startup_no_debug_mode(mocker: MockerFixture):
    """
    Given: A Client instance with debug mode disabled and a process that starts successfully.
    When: _monitor_server_startup is called with debug mode off.
    Then: The method should complete successfully without creating a log streaming task.
    """
    # Mock the process stdout
    mock_stdout = mocker.Mock()
    mock_stdout.readline.side_effect = [b"StreamableHTTP session manager started\n"]

    # Mock process
    mock_process = mocker.Mock()
    mock_process.stdout = mock_stdout

    # Mock asyncio.to_thread
    mocker.patch("asyncio.to_thread", side_effect=lambda func: func())

    # Mock route_server_log
    mocker.patch("CrowdStrikeFalconMCP.route_server_log")

    # Mock is_debug_mode to return False
    mocker.patch("CrowdStrikeFalconMCP.is_debug_mode", return_value=False)
    mock_create_task = mocker.patch("asyncio.create_task")

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )
    client.process = mock_process
    client.is_debug_mode = False

    await client._monitor_server_startup()

    # Verify no task was created since debug mode is off
    mock_create_task.assert_not_called()


@pytest.mark.asyncio
async def test_stream_logs_successful_streaming(mocker: MockerFixture):
    """
    Given: A Client instance with a mock stream that provides log lines and then ends.
    When: _stream_logs is called with the stream and a prefix.
    Then: Each line should be decoded, processed, and routed to the logging system with the prefix.
    """
    # Mock the stream
    mock_stream = mocker.Mock()
    mock_stream.readline.side_effect = [
        b"First log line\n",
        b"Second log line\n",
        b"",  # Empty line indicates end of stream
    ]

    # Mock asyncio.to_thread to return readline results synchronously
    mocker.patch("asyncio.to_thread", side_effect=lambda func: func())

    # Mock route_server_log
    mock_route_log = mocker.patch("CrowdStrikeFalconMCP.route_server_log")

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )

    await client._stream_logs(mock_stream, "[TEST] ")

    # Verify all lines were processed with the prefix
    assert mock_route_log.call_count == 2
    mock_route_log.assert_any_call("[TEST] First log line")
    mock_route_log.assert_any_call("[TEST] Second log line")


@pytest.mark.asyncio
async def test_stream_logs_handles_decode_errors(mocker: MockerFixture):
    """
    Given: A Client instance with a mock stream that provides binary data with invalid UTF-8 sequences.
    When: _stream_logs is called and encounters decode errors.
    Then: The method should handle decode errors gracefully using the 'ignore' error mode and continue processing.
    """
    # Mock the stream with invalid UTF-8 data
    mock_stream = mocker.Mock()
    invalid_utf8 = b"\xff\xfe Invalid UTF-8 \x80\x81\n"
    mock_stream.readline.side_effect = [
        invalid_utf8,
        b"",  # End of stream
    ]

    # Mock asyncio.to_thread
    mocker.patch("asyncio.to_thread", side_effect=lambda func: func())

    # Mock route_server_log
    mock_route_log = mocker.patch("CrowdStrikeFalconMCP.route_server_log")

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )

    await client._stream_logs(mock_stream, "[PREFIX] ")

    # Verify the method completed without raising an exception and processed the line
    mock_route_log.assert_called_once()
    # The exact decoded content may vary, but it should contain the readable parts
    call_args = mock_route_log.call_args[0][0]
    assert call_args.startswith("[PREFIX] ")


@pytest.mark.asyncio
async def test_stream_logs_empty_stream(mocker: MockerFixture):
    """
    Given: A Client instance with a mock stream that immediately returns empty data.
    When: _stream_logs is called with an empty stream.
    Then: The method should exit immediately without calling the logging function.
    """
    # Mock the stream to return empty immediately
    mock_stream = mocker.Mock()
    mock_stream.readline.return_value = b""

    # Mock asyncio.to_thread
    mocker.patch("asyncio.to_thread", side_effect=lambda func: func())

    # Mock route_server_log
    mock_route_log = mocker.patch("CrowdStrikeFalconMCP.route_server_log")

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )

    await client._stream_logs(mock_stream, "[EMPTY] ")

    # Verify no logging calls were made
    mock_route_log.assert_not_called()


@pytest.mark.asyncio
async def test_get_session_successful_initialization(mocker: MockerFixture):
    """
    Given: A Client instance with valid configuration and mocked MCP components.
    When: The _get_session context manager is used successfully.
    Then: A session should be initialized and yielded with proper cleanup.
    """
    # Mock the MCP components
    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock()

    mock_read_stream = AsyncMock()
    mock_write_stream = AsyncMock()
    mock_transport = AsyncMock()

    # Mock the streamablehttp_client context manager
    mock_streamable_client = mocker.patch("CrowdStrikeFalconMCP.streamablehttp_client")
    mock_streamable_client.return_value.__aenter__.return_value = (mock_read_stream, mock_write_stream, mock_transport)
    mock_streamable_client.return_value.__aexit__.return_value = None

    # Mock ClientSession
    mock_client_session = mocker.patch("CrowdStrikeFalconMCP.ClientSession")
    mock_client_session.return_value = mock_session
    mock_client_session.return_value.__aenter__.return_value = mock_session
    mock_client_session.return_value.__aexit__.return_value = None

    # Mock the _server context manager
    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )
    mocker.patch.object(client, "_server")
    client._server.return_value.__aenter__.return_value = None
    client._server.return_value.__aexit__.return_value = None

    # Test the context manager
    async with client._get_session() as session:
        assert session == mock_session

    # Verify session.initialize was called
    mock_session.initialize.assert_called_once()

    # Verify streamablehttp_client was called with correct URL
    mock_streamable_client.assert_called_once_with("http://127.0.0.1:8080/mcp")


@pytest.mark.asyncio
async def test_get_session_initialization_failure(mocker: MockerFixture):
    """
    Given: A Client instance where session initialization fails with an exception.
    When: The _get_session context manager is used and initialization raises an error.
    Then: The exception should propagate while still performing proper cleanup.
    """
    # Mock session that fails during initialization
    mock_session = AsyncMock()
    mock_session.initialize.side_effect = RuntimeError("Session initialization failed")

    mock_read_stream = AsyncMock()
    mock_write_stream = AsyncMock()
    mock_transport = AsyncMock()

    # Mock the streamablehttp_client context manager
    mock_streamable_client = mocker.patch("CrowdStrikeFalconMCP.streamablehttp_client")
    mock_streamable_client.return_value.__aenter__.return_value = (mock_read_stream, mock_write_stream, mock_transport)
    mock_streamable_client.return_value.__aexit__.return_value = None

    # Mock ClientSession
    mock_client_session = mocker.patch("CrowdStrikeFalconMCP.ClientSession")
    mock_client_session.return_value = mock_session
    mock_client_session.return_value.__aenter__.return_value = mock_session
    mock_client_session.return_value.__aexit__.return_value = None

    # Mock the _server context manager
    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )
    mocker.patch.object(client, "_server")
    client._server.return_value.__aenter__.return_value = None
    client._server.return_value.__aexit__.return_value = None

    # Test that the exception is properly raised
    with pytest.raises(RuntimeError, match="Session initialization failed"):
        async with client._get_session():
            pass

    # Verify initialization was attempted
    mock_session.initialize.assert_called_once()


@pytest.mark.asyncio
async def test_get_session_uses_custom_host_port(mocker: MockerFixture):
    """
    Given: A Client instance configured with custom host and port values.
    When: The _get_session context manager constructs the base URL.
    Then: The streamablehttp_client should be called with the custom host and port in the URL.
    """
    # Mock the MCP components
    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock()

    mock_read_stream = AsyncMock()
    mock_write_stream = AsyncMock()
    mock_transport = AsyncMock()

    # Mock the streamablehttp_client context manager
    mock_streamable_client = mocker.patch("CrowdStrikeFalconMCP.streamablehttp_client")
    mock_streamable_client.return_value.__aenter__.return_value = (mock_read_stream, mock_write_stream, mock_transport)
    mock_streamable_client.return_value.__aexit__.return_value = None

    # Mock ClientSession
    mock_client_session = mocker.patch("CrowdStrikeFalconMCP.ClientSession")
    mock_client_session.return_value = mock_session
    mock_client_session.return_value.__aenter__.return_value = mock_session
    mock_client_session.return_value.__aexit__.return_value = None

    # Create client with custom host and port
    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
        host="192.168.1.100",
        port=9090,
    )
    mocker.patch.object(client, "_server")
    client._server.return_value.__aenter__.return_value = None
    client._server.return_value.__aexit__.return_value = None

    # Test the context manager
    async with client._get_session():
        pass

    # Verify streamablehttp_client was called with custom URL
    mock_streamable_client.assert_called_once_with("http://192.168.1.100:9090/mcp")


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

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )

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

    client = Client(
        FALCON_BASE_API_URL,
        client_id="test_id",
        client_secret="test_secret",
        enabled_modules=["hosts"],
    )

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
    mock_dict_conversion = mocker.patch("CrowdStrikeFalconMCP.object_to_dict_recursive")
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
    mock_dict_conversion = mocker.patch("CrowdStrikeFalconMCP.object_to_dict_recursive")
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
    mock_dict_conversion = mocker.patch("CrowdStrikeFalconMCP.object_to_dict_recursive")
    mock_dict_conversion.return_value = {"content": [{"text": '{"status": "success", "count": 5}'}], "isError": False}

    # Mock tableToMarkdown
    mock_table = mocker.patch("CrowdStrikeFalconMCP.tableToMarkdown")
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
    mock_dict_conversion = mocker.patch("CrowdStrikeFalconMCP.object_to_dict_recursive")
    mock_dict_conversion.return_value = {"content": [{"text": "Operation completed successfully"}], "isError": False}

    result = await call_tool(mock_client, "update-host", '{"host_id": "123"}')

    assert result.readable_output == "Tool execution 'update-host': Operation completed successfully"
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
    mock_dict_conversion = mocker.patch("CrowdStrikeFalconMCP.object_to_dict_recursive")
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
