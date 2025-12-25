import demistomock as demisto
from CommonServerPython import *
from contextlib import asynccontextmanager
import asyncio
from asyncio import Task

from mcp.client.streamable_http import streamablehttp_client
import subprocess

from typing import IO

from mcp import ClientSession

from mcp.types import CallToolResult, TextContent


DEFAULT_REGION_SUFFIX = "US-1"
API_REGION_SUFFIX = {
    DEFAULT_REGION_SUFFIX: "",
    "US-2": "us-2.",
    "EU-1": "eu-1.",
    "US-GOV": "laggar.gcw.",
}
BASE_FALCON_API_URL = "https://api.{}crowdstrike.com"
SERVER_LOG_PREFIX = "[FALCON MCP SERVER] "


def extract_root_error_message(exception):
    """
    Extract the root error message from an exception, handling nested exception groups.

    Args:
        exception: The exception to extract the error message from

    Returns:
        Formatted error message string from the root cause exception.
    """
    if isinstance(exception, BaseExceptionGroup | ExceptionGroup) and exception.exceptions:
        # Recursively check the first inner exception
        return extract_root_error_message(exception.exceptions[0])

    # Format and return the message for a regular exception
    return "".join(traceback.format_exception_only(type(exception), exception))


def object_to_dict_recursive(obj):
    """
    Recursively convert an object to a dictionary representation.

    Args:
        obj: The object to convert (custom objects, lists, tuples, sets, dicts, or primitives)

    Returns:
        Dictionary representation of the object with nested objects also converted to dictionaries.
        Primitive types are returned as-is.
    """
    if hasattr(obj, "__dict__"):
        # 1. Convert Custom Objects
        # Get all attributes of the object that aren't callable (methods)
        data = {
            key: object_to_dict_recursive(value)
            for key, value in obj.__dict__.items()
            if not key.startswith("__") and not callable(value)
        }
        return data

    elif isinstance(obj, list | tuple | set):
        # 2. Convert Iterables
        # Convert each item in the iterable
        return [object_to_dict_recursive(item) for item in obj]

    elif isinstance(obj, dict):
        # 3. Convert Dictionaries
        # Convert dictionary values recursively
        return {key: object_to_dict_recursive(value) for key, value in obj.items()}

    else:
        # 4. Base Case
        # Return primitive types (int, str, bool, etc.) as is
        return obj


def get_text_from_call_result(call_result: CallToolResult):
    """
    Extract text from a call result object recursively, handling various result types.

    Args:
        call_result: The result object from a method call

    Returns:
        Extracted text or string representation of the result.
    """
    text = ""

    if call_result.content and isinstance(call_result.content[0], TextContent):
        text = call_result.content[0].text

    return text


def route_server_log(line: str):
    """
    Routes a server log line to the appropriate Demisto logging function
    based on the log level in the line.
    """
    line = line.strip()
    if "- DEBUG -" in line:
        demisto.debug(line)
    elif "- INFO -" in line:
        demisto.info(line)
    else:
        # Default to info if log level is not recognized
        demisto.info(line)


class Client:
    def __init__(
        self,
        falcon_base_api_url: str,
        client_id: str,
        client_secret: str,
        enabled_modules: list[str],
        host: str = "127.0.0.1",
        port: int = 8080,
    ):
        """
        Initialize the Client with CrowdStrike Falcon MCP server configuration.

        Args:
            falcon_base_api_url: Base URL for CrowdStrike Falcon API
            client_id: CrowdStrike Falcon client ID for authentication
            client_secret: CrowdStrike Falcon client secret for authentication
            enabled_modules: List of MCP modules to enable
            host: Host address for the MCP server (defaults to "127.0.0.1")
            port: Port number for the MCP server (defaults to 8080)
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.enabled_modules = enabled_modules
        self.host = host
        self.port = port
        self.process: subprocess.Popen
        self.base_url = f"http://{host}:{port}/mcp"
        self.falcon_base_api_url = falcon_base_api_url
        self.is_debug_mode = is_debug_mode()
        self._stream_task: Task[Any] | None = None

    @asynccontextmanager
    async def _server(self):
        """Start falcon-mcp and tear it down automatically."""

        process_args = [
            "falcon-mcp",
            "--transport",
            "streamable-http",
            "--host",
            self.host,
            "--port",
            str(self.port),
        ]

        env = dict(
            os.environ,
            FALCON_CLIENT_ID=self.client_id,
            FALCON_CLIENT_SECRET=self.client_secret,
            FALCON_BASE_URL=self.falcon_base_api_url,
            FALCON_MCP_MODULES=",".join(self.enabled_modules),
            FALCON_MCP_DEBUG=str(self.is_debug_mode).lower(),
        )

        self.process = subprocess.Popen(
            args=process_args,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            await self._monitor_server_startup()
            yield
        finally:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()

    async def _monitor_server_startup(self):
        assert self.process.stdout is not None
        stdout = self.process.stdout
        startup_keyword = "StreamableHTTP session manager started"

        while True:
            line = await asyncio.to_thread(stdout.readline)
            if not line:
                raise RuntimeError("Server process exited before startup")
            text = line.decode(errors="ignore").strip()

            route_server_log(f"{SERVER_LOG_PREFIX}{text}")

            if startup_keyword in text:
                break
        if self.is_debug_mode:
            self._stream_task = asyncio.create_task(self._stream_logs(stdout, prefix=SERVER_LOG_PREFIX))

    async def _stream_logs(self, stream: IO[Any], prefix: str):
        while True:
            line = await asyncio.to_thread(stream.readline)
            if not line:
                break
            text = line.decode(errors="ignore").strip()
            route_server_log(prefix + text)

    @asynccontextmanager
    async def _get_session(self):
        """
        Initializes an MCP session over HTTP with the server.
        """
        async with (
            self._server(),
            streamablehttp_client(self.base_url) as (
                read_stream,
                write_stream,
                _,
            ),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            yield session

    async def test_connection(self):
        async with self._get_session():
            return "ok"

    async def list_tools(self):
        async with self._get_session() as session:
            return await session.list_tools()

    async def call_tool(self, tool_name, arguments):
        async with self._get_session() as session:
            return await session.call_tool(tool_name, arguments)


async def list_tools(client: Client):
    """
    Lists all available tools from the GitHub MCP client.

    Args:
        client (Client): The initialized GitHub MCP client

    Returns:
        CommandResults: Formatted command results containing tool list and metadata
    """
    tools = await client.list_tools()

    tools = tools.tools
    tool_names = [tool.name for tool in tools]

    readable_output = f"Available {len(tool_names)} tools:\n{tool_names}"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ListTools.Tools",
        outputs=object_to_dict_recursive(tools),
    )


async def call_tool(client: Client, tool_name: str, arguments: str) -> CommandResults:
    """
    Calls a specific tool with given arguments and returns results.

    Args:
        client (Client): The initialized GitHub MCP client
        tool_name (str): Name of the tool to call
        arguments (str): Arguments for the tool in dictionary format

    Returns:
        CommandResults: Formatted command results from tool execution
    """
    try:
        arguments = json.loads(arguments)
    except json.JSONDecodeError:
        raise DemistoException(f"Invalid JSON provided for arguments: {arguments}")

    result = await client.call_tool(tool_name, arguments)

    result_content = get_text_from_call_result(result)

    if result.isError:
        readable_output = f"Tool execution '{tool_name}' failed: {result_content}."
    else:
        try:
            readable_output = tableToMarkdown(f"Tool execution '{tool_name}'", json.loads(result_content))
        except json.JSONDecodeError:
            readable_output = f"Tool execution '{tool_name}': {result_content}"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CallTool.Tool",
        outputs=object_to_dict_recursive(result),
        entry_type=EntryType.NOTE if not result.isError else EntryType.ERROR,
    )


""" MAIN FUNCTION """


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    client_id = params.get("credentials", {}).get("identifier")
    client_secret = params.get("credentials", {}).get("password")
    enabled_modules = argToList(params.get("enabled_modules"))
    api_region = params.get("api_region") or DEFAULT_REGION_SUFFIX
    falcon_base_api_url = BASE_FALCON_API_URL.format(API_REGION_SUFFIX[api_region])

    try:
        client = Client(
            falcon_base_api_url=falcon_base_api_url,
            client_id=client_id,
            client_secret=client_secret,
            enabled_modules=enabled_modules,
        )

        if command == "test-module":
            result = await client.test_connection()
            return_results(result)
        if command == "list-tools":
            result = await list_tools(client)
            return_results(result)
        elif command == "call-tool":
            result = await call_tool(client, args["name"], args.get("arguments") or "{}")
            return_results(result)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except BaseException as eg:
        root_msg = extract_root_error_message(eg)
        return_error(f"Failed to execute {command} command.\nError:\n{root_msg}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
