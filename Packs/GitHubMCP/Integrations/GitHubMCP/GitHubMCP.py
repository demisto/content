import demistomock as demisto
from CommonServerPython import *
from MCPApiModule import *

import asyncio


GITHUB_BASE_URL = "https://api.githubcopilot.com/mcp"
GITHUB_AUTH_TYPE = AuthMethods.BEARER.value


""" MAIN FUNCTION """


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    token = params.get("token", {}).get("password")
    toolsets = argToList(params.get("enabled_toolsets"))
    readonly = argToBoolean(params.get("readonly"))
    custom_headers = {
        "X-MCP-Toolsets": ",".join(toolsets),
        "X-MCP-Readonly": str(readonly).lower(),
    }

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=GITHUB_BASE_URL,
            auth_type=GITHUB_AUTH_TYPE,
            token=token,
            custom_headers=custom_headers,
        )
        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            result = await client.test_connection()
            return_results(result)

        elif command == "list-tools":
            result = await client.list_tools()
            return_results(result)

        elif command == "call-tool":
            result = await client.call_tool(args["name"], args.get("arguments", ""))
            return_results(result)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except BaseException as eg:
        root_msg = extract_root_error_message(eg)
        return_error(f"Failed to execute {command} command.\nError:\n{root_msg}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
