import demistomock as demisto
from CommonServerPython import *
from MCPApiModule import *

import asyncio


from urllib.parse import unquote


ATLASSIAN_BASE_URL = "https://mcp.atlassian.com/v1/mcp"
ATLASSIAN_REDIRECT_URI = "http://127.0.0.1:8000/callback"
ATLASSIAN_AUTH_TYPE = AuthMethods.DYNAMIC_CLIENT_REGISTRATION.value
COMMAND_PREFIX = "atlassian-cloud-mcp"
SERVER_NAME = "Atlassian Cloud MCP"


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    try:
        auth_code = unquote(params.get("auth_code", {}).get("password") or "")

        client = Client(
            base_url=ATLASSIAN_BASE_URL,
            command_prefix=COMMAND_PREFIX,
            auth_type=ATLASSIAN_AUTH_TYPE,
            auth_code=auth_code,
            redirect_uri=ATLASSIAN_REDIRECT_URI,
        )
        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            raise DemistoException(
                "\nTest module is unavailable for this integration. "
                f"Please use the **!{COMMAND_PREFIX}-auth-test** command to test "
                "connectivity after setting the Authorization Code.",
            )

        elif command == "list-tools":
            result = await client.list_tools(SERVER_NAME)
            return_results(result)

        elif command == "call-tool":
            result = await client.call_tool(args["name"], args.get("arguments", ""))
            return_results(result)

        elif command == f"{COMMAND_PREFIX}-auth-test":
            result = await client.test_connection(auth_test=True)
            return_results(result)

        elif command == f"{COMMAND_PREFIX}-generate-login-url":
            result = await generate_login_url(
                client._oauth_handler, auth_type=ATLASSIAN_AUTH_TYPE, redirect_uri=ATLASSIAN_REDIRECT_URI
            )
            return_results(result)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except BaseException as eg:
        root_msg = extract_root_error_message(eg)
        return_error(f"Failed to execute {command} command.\nError:\n{root_msg}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
