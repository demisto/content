import demistomock as demisto
from CommonServerPython import *
from MCPApiModule import *

import asyncio

COMMAND_PREFIX = "nodezero-mcp"
DEFAULT_BASE_URL = "https://mcp.horizon3ai.com"


def validate_required_params(base_url: str) -> None:
    """Validates that required parameters are present.

    With Dynamic Client Registration the client_id and token_endpoint are
    discovered and registered automatically — only the MCP server URL is needed.
    """
    if not base_url:
        raise ValueError("Server URL must be provided.")


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    client = None
    try:
        base_url = params.get("base_url", DEFAULT_BASE_URL)
        scope = params.get("scope", "")
        redirect_uri = params.get("redirect_uri", "") or REDIRECT_URI
        server_name = params.get("server_name", "")

        validate_required_params(base_url)

        client = Client(
            base_url=base_url,
            auth_type=AuthMethods.DYNAMIC_CLIENT_REGISTRATION,
            command_prefix=COMMAND_PREFIX,
            scope=scope,
            redirect_uri=redirect_uri,
        )
        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            raise DemistoException(
                f"\nTest module is unavailable for OAuth 2.0 Dynamic Client Registration.\n"
                f"Please use the !{COMMAND_PREFIX}-auth-test command to test connectivity.",
            )

        elif command == "list-tools":
            result = await client.list_tools(server_name)
            return_results(result)

        elif command == "call-tool":
            result = await client.call_tool(args["name"], args.get("arguments", ""))
            return_results(result)

        elif command == f"{COMMAND_PREFIX}-auth-test":
            result = await client.test_connection(auth_test=True)
            return_results(result)

        elif command == f"{COMMAND_PREFIX}-generate-login-url":
            result = await generate_login_url(
                client._oauth_handler, AuthMethods.DYNAMIC_CLIENT_REGISTRATION, redirect_uri=redirect_uri
            )
            return_results(result)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except BaseException as eg:
        root_msg = extract_root_error_message(eg)
        return_error(f"Failed to execute {command} command.\nError:\n{root_msg}")

    finally:
        if client:
            demisto.debug(f"Closing client connection for {command}")
            await client.close()


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
