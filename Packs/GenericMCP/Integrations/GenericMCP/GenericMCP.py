import demistomock as demisto
from CommonServerPython import *

import asyncio

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


def object_to_dict_recursive(obj):
    """
    Recursively converts a Python object to a dictionary.
    Handles custom objects, lists, and dictionaries.
    """
    if hasattr(obj, "__dict__"):
        # 1. Convert Custom Objects
        # Get all attributes of the object that aren't callable (methods)
        data = dict(
            [
                (key, object_to_dict_recursive(value))
                for key, value in obj.__dict__.items()
                if not key.startswith("__") and not callable(value)
            ]
        )
        return data

    elif isinstance(obj, (list, tuple, set)):
        # 2. Convert Iterables
        # Convert each item in the iterable
        return [object_to_dict_recursive(item) for item in obj]

    elif isinstance(obj, dict):
        # 3. Convert Dictionaries
        # Convert dictionary values recursively
        return dict([(key, object_to_dict_recursive(value)) for key, value in obj.items()])

    else:
        # 4. Base Case
        # Return primitive types (int, str, bool, etc.) as is
        return obj


class Client:
    def __init__(
        self,
        base_url: str,
        token: str,
    ):
        self.base_url = base_url
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
        }

    async def test_connection(self):
        async with streamablehttp_client(self.base_url, headers=self.headers) as (
            read_stream,
            write_stream,
            _,
        ):
            async with ClientSession(read_stream, write_stream) as session:
                # Initialize the connection
                await session.initialize()
                return "ok"

    async def list_tools(self):
        async with streamablehttp_client(self.base_url, headers=self.headers) as (
            read_stream,
            write_stream,
            _,
        ):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                tool_names = [tool.name for tool in tools.tools]
                readable_output = tableToMarkdown("Available tools", tool_names)
                demisto.debug(f"Available tools: {tool_names}")
                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix="ListTools.Tools",
                    outputs_key_field="name",
                    outputs=object_to_dict_recursive(tools.tools),
                )

    async def call_tool(self, tool_name, arguments):
        async with streamablehttp_client(self.base_url, headers=self.headers) as (
            read_stream,
            write_stream,
            _,
        ):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments)
                result_content = object_to_dict_recursive(result.content)
                readable_output = tableToMarkdown("Tool Execution Details", object_to_dict_recursive(result_content))
                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix="CallTool.Tool",
                    outputs_key_field="name",
                    outputs=object_to_dict_recursive(result_content),
                )


""" MAIN FUNCTION """


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    client = Client(
        base_url=params.get("base_url"),
        token=params.get("token"),
    )
    demisto.debug(f"Command being called is {command}")
    try:
        if command == "test-module":
            result = await client.test_connection()
            return_results(result)
        if command == "list-tools":
            result = await client.list_tools()
            return_results(result)
        elif command == "call-tool":
            result = await client.call_tool(args.get("name"), args.get("arguments"))
            return_results(result)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
