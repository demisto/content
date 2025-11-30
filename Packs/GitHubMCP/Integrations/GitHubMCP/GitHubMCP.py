import demistomock as demisto
from CommonServerPython import *

from contextlib import asynccontextmanager
import asyncio

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import CallToolResult, TextContent

BASE_URL = "https://api.githubcopilot.com/mcp/"


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


class Client:
    def __init__(
        self,
        base_url: str,
        token: str,
        toolsets: list[str],
        readonly: bool,
    ):
        """
        Initialize the GitHub MCP client with connection parameters.

        Args:
            base_url (str): The base URL for the MCP server
            token (str): Authentication token for GitHub API access
            toolsets (list[str]): List of available toolsets to enable
            readonly (bool): Whether to operate in read-only mode
        """
        self.base_url = base_url
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "X-MCP-Toolsets": ",".join(toolsets),
            "X-MCP-Readonly": str(readonly).lower(),
        }

    @asynccontextmanager
    async def _get_session(self):
        """
        Creates and initializes an async context manager for MCP client session.

        Establishes a streamable HTTP connection to the MCP server and creates a client session
        for communication. The session is automatically initialized and cleaned up when the
        context exits.

        Yields:
            ClientSession: An initialized MCP client session for making requests
        """
        async with (
            streamablehttp_client(self.base_url, headers=self.headers) as (
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
        arguments (dict): Arguments for the tool execution

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
            readable_output = tableToMarkdown(f"Tool Execution '{tool_name}'", json.loads(result_content))
        except json.JSONDecodeError:
            readable_output = f"Tool Execution '{tool_name}': {result_content}"

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

    token = params.get("token", {}).get("password")
    toolsets = argToList(params.get("enabled_toolsets"))
    readonly = argToBoolean(params.get("readonly"))

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=BASE_URL,
            token=token,
            toolsets=toolsets,
            readonly=readonly,
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
