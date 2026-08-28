import demistomock as demisto
from CommonServerPython import *
from MCPApiModule import *

import asyncio
from urllib.parse import unquote

COMMAND_PREFIX = "nodezero-mcp"
DEFAULT_BASE_URL = "https://mcp.horizon3ai.com"
SCOPE = "read write offline_access"


def validate_required_params(base_url: str, auth_code: str, command: str) -> None:
    if not base_url:
        raise ValueError("Server URL must be provided.")
    if not auth_code and command not in ("test-module", f"{COMMAND_PREFIX}-generate-login-url"):
        raise ValueError("Authorization Code is required. Run !nodezero-mcp-generate-login-url to obtain one.")


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    client = None
    try:
        base_url = params.get("base_url", DEFAULT_BASE_URL)
        auth_code = unquote(params.get("auth_code", {}).get("password") or "")

        validate_required_params(base_url, auth_code, command)

        client = Client(
            base_url=base_url,
            auth_type=AuthMethods.DYNAMIC_CLIENT_REGISTRATION,
            command_prefix=COMMAND_PREFIX,
            scope=SCOPE,
            redirect_uri=REDIRECT_URI,
            auth_code=auth_code,
        )
        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            raise DemistoException(
                f"\nTest module is unavailable for OAuth 2.0 Dynamic Client Registration.\n"
                f"Please use the !{COMMAND_PREFIX}-auth-test command to test connectivity.",
            )

        elif command == "list-tools":
            result = await client.list_tools(COMMAND_PREFIX)
            return_results(result)

        elif command == "call-tool":
            result = await client.call_tool(args["name"], args.get("arguments", ""))
            return_results(result)

        elif command == f"{COMMAND_PREFIX}-auth-test":
            result = await client.test_connection(auth_test=True)
            return_results(result)

        elif command == f"{COMMAND_PREFIX}-generate-login-url":
            result = await generate_login_url(client._oauth_handler, AuthMethods.DYNAMIC_CLIENT_REGISTRATION)
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
