import demistomock as demisto
from CommonServerPython import *
from MCPApiModule import *

import asyncio


from urllib.parse import unquote


REGION_URLS = {
    "North America": "https://mcp.cmdzero.io/",
    "European Union": "https://mcp.eu.cmdzero.io/",
}
COMMAND_ZERO_AUTH_TYPE = AuthMethods.DYNAMIC_CLIENT_REGISTRATION.value
COMMAND_PREFIX = "command-zero-mcp"
SERVER_NAME = "Command Zero MCP"
NO_LOGIN_SESSION_MESSAGE = (
    "No Command Zero login session was found for this instance. "
    f"Run the **!{COMMAND_PREFIX}-generate-login-url** command, sign in, copy the new Authorization code into the "
    f"instance configuration, and run **!{COMMAND_PREFIX}-auth-test** within two minutes."
)


def get_base_url(params: dict[str, Any]) -> str:
    """Returns the custom server URL when set, otherwise the URL of the selected region."""
    custom_url = (params.get("server_url") or "").strip()
    if custom_url:
        return custom_url

    region = params.get("region") or "North America"
    if region not in REGION_URLS:
        raise DemistoException(f"Unsupported region '{region}'. Supported regions: {', '.join(REGION_URLS)}.")
    return REGION_URLS[region]


def has_login_session() -> bool:
    """Returns True when a login URL was generated for this instance, which stores the discovered token endpoint."""
    return bool(get_integration_context().get("token_endpoint"))


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    client = None
    try:
        auth_code = unquote(params.get("auth_code", {}).get("password") or "")
        redirect_uri = params.get("redirect_uri") or REDIRECT_URI

        client = Client(
            base_url=get_base_url(params),
            command_prefix=COMMAND_PREFIX,
            auth_type=COMMAND_ZERO_AUTH_TYPE,
            auth_code=auth_code,
            redirect_uri=redirect_uri,
            custom_headers=parse_custom_headers(params.get("custom_headers") or ""),
            verify=not argToBoolean(params.get("insecure") or False),
        )
        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            raise DemistoException(
                "\nTest module is unavailable for this integration. "
                f"Please use the **!{COMMAND_PREFIX}-auth-test** command to test "
                "connectivity after setting the Authorization Code.",
            )

        elif command == f"{COMMAND_PREFIX}-generate-login-url":
            result = await generate_login_url(client._oauth_handler, auth_type=COMMAND_ZERO_AUTH_TYPE, redirect_uri=redirect_uri)
            return_results(result)

        elif command == f"{COMMAND_PREFIX}-auth-test" and not has_login_session():
            demisto.debug("No login session found, generating a login URL instead of testing authentication.")
            result = await generate_login_url(client._oauth_handler, auth_type=COMMAND_ZERO_AUTH_TYPE, redirect_uri=redirect_uri)
            result.readable_output = f"No Command Zero login session was found for this instance.\n\n{result.readable_output}"
            return_results(result)

        elif not has_login_session():
            raise DemistoException(NO_LOGIN_SESSION_MESSAGE)

        elif command == "list-tools":
            result = await client.list_tools(SERVER_NAME)
            return_results(result)

        elif command == "call-tool":
            result = await client.call_tool(args["name"], args.get("arguments", ""))
            return_results(result)

        elif command == f"{COMMAND_PREFIX}-auth-test":
            result = await client.test_connection(auth_test=True)
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
