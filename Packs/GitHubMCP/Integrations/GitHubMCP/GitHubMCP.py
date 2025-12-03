import demistomock as demisto
from CommonServerPython import *

from contextlib import asynccontextmanager
import asyncio

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

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
            ClientSession(read_stream, write_stream) as session,  # pylint: disable=E0601
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

    tool_names = [tool.name for tool in tools.tools]
    readable_output = f"Available {len(tool_names)} tools:\n{tool_names}"

    tools_dump = tools.model_dump(mode="json")

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ListTools.Tools",
        outputs=tools_dump.get("tools", []),
    )


async def call_tool(client: Client, tool_name: str, arguments: str) -> CommandResults:
    """
    Calls a specific tool with given arguments and returns results.

    Args:
        client (Client): The initialized GitHub MCP client
        tool_name (str): Name of the tool to call
        arguments (str): Arguments for the tool execution

    Returns:
        CommandResults: Formatted command results from tool execution
    """
    try:
        parsed_arguments = json.loads(arguments or "{}")
    except json.JSONDecodeError:
        raise DemistoException(f"Invalid JSON provided for arguments: {arguments}")

    result = await client.call_tool(tool_name, parsed_arguments)

    result_dump = result.model_dump(mode="json")
    result_content = result_dump.get("content", [])
    readable_output = tableToMarkdown(f"Tool Execution '{tool_name}'{' failed' if result.isError else ''}", result_content)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CallTool.Tool",
        outputs=result_content,
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
            result = await call_tool(client, args["name"], args.get("arguments", ""))
            return_results(result)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except BaseException as eg:
        root_msg = extract_root_error_message(eg)
        return_error(f"Failed to execute {command} command.\nError:\n{root_msg}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
