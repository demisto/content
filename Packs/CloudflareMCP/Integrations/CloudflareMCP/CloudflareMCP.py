import demistomock as demisto
from CommonServerPython import *
from MCPApiModule import *

import asyncio


from urllib.parse import unquote


CLOUDFLARE_BASE_URL = "https://{server}.mcp.cloudflare.com/mcp"
CLOUDFLARE_AUTH_TYPE = AuthMethods.DYNAMIC_CLIENT_REGISTRATION.value
COMMAND_PREFIX = "cloudflare-mcp"
SERVERS_NO_AUTHORIZATION = ["docs"]


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    try:
        cloudflare_server = params.get("cloudflare_server", "")
        cloudflare_url = CLOUDFLARE_BASE_URL.format(server=cloudflare_server)
        auth_type = AuthMethods.NO_AUTHORIZATION.value if cloudflare_server in SERVERS_NO_AUTHORIZATION else CLOUDFLARE_AUTH_TYPE
        auth_code = unquote(params.get("auth_code", {}).get("password") or "")
        redirect_uri = params.get("redirect_uri") or REDIRECT_URI

        client = Client(
            base_url=cloudflare_url,
            command_prefix=COMMAND_PREFIX,
            auth_type=auth_type,
            auth_code=auth_code,
            redirect_uri=redirect_uri,
        )
        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            if cloudflare_server in SERVERS_NO_AUTHORIZATION:
                result = await client.test_connection()
                return_results(result)
            else:
                raise DemistoException(
                    "\nTest module is unavailable for this integration. "
                    f"Please use the **!{COMMAND_PREFIX}-auth-test** command to test "
                    "connectivity after setting the Authorization Code.",
                )

        elif command == "list-tools":
            result = await client.list_tools()
            return_results(result)

        elif command == "call-tool":
            result = await client.call_tool(args["name"], args.get("arguments", ""))
            return_results(result)

        elif command == f"{COMMAND_PREFIX}-auth-test":
            result = await client.test_connection(auth_test=True)
            return_results(result)

        elif command == f"{COMMAND_PREFIX}-generate-login-url":
            result = await generate_login_url(
                client._oauth_handler, auth_type=CLOUDFLARE_AUTH_TYPE, redirect_uri=redirect_uri, troubleshooting_redirect=True
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
