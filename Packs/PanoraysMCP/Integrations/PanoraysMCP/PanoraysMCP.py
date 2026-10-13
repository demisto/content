import demistomock as demisto
from CommonServerPython import *
from MCPApiModule import *

import asyncio

from urllib.parse import unquote


PANORAYS_MCP_URL = "https://mcp.panoraysapp.com/mcp"
PANORAYS_AUTHORIZATION_ENDPOINT = "https://auth.panoraysapp.com/op/auth"
PANORAYS_TOKEN_ENDPOINT = "https://auth.panoraysapp.com/op/token"
PANORAYS_SCOPE = "openid offline_access features permissions"
SUPPORTED_AUTH_TYPES = (AuthMethods.BEARER.value, AuthMethods.AUTHORIZATION_CODE.value)
COMMAND_PREFIX = "panorays-mcp"
SERVER_NAME = "Panorays Axis MCP"


def validate_required_params(auth_type: str, token: str, client_id: str, client_secret: str) -> None:
    """Validates that the parameters required by the selected authentication type are present.

    Args:
        auth_type: The selected authentication type.
        token: The Panorays API token, used for Bearer authentication.
        client_id: The OAuth Client ID, used for OAuth authentication.
        client_secret: The OAuth Client Secret, used for OAuth authentication.
    """
    if auth_type not in SUPPORTED_AUTH_TYPES:
        raise ValueError(f"Unsupported authentication type: {auth_type}. Supported types: {', '.join(SUPPORTED_AUTH_TYPES)}.")
    if auth_type == AuthMethods.BEARER and not token:
        raise ValueError("API Token is required for Bearer authentication.")
    if auth_type == AuthMethods.AUTHORIZATION_CODE and not all((client_id, client_secret)):
        raise ValueError("Client ID and Client Secret are required for OAuth authentication.")


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    client = None
    try:
        auth_type = params.get("auth_type", "")
        token = params.get("token", {}).get("password", "")
        client_id = params.get("oauth_credentials", {}).get("identifier", "")
        client_secret = params.get("oauth_credentials", {}).get("password", "")
        auth_code = unquote(params.get("auth_code", {}).get("password") or "")
        redirect_uri = params.get("redirect_uri", "") or REDIRECT_URI

        validate_required_params(auth_type, token, client_id, client_secret)

        client = Client(
            base_url=PANORAYS_MCP_URL,
            auth_type=auth_type,
            command_prefix=COMMAND_PREFIX,
            token=token,
            client_id=client_id,
            client_secret=client_secret,
            auth_code=auth_code,
            token_endpoint=PANORAYS_TOKEN_ENDPOINT,
            scope=PANORAYS_SCOPE,
            redirect_uri=redirect_uri,
        )
        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            if auth_type == AuthMethods.AUTHORIZATION_CODE:
                raise DemistoException(
                    f"\nTest module is unavailable for this authentication type: {auth_type}.\n"
                    f"Please use the **!{COMMAND_PREFIX}-auth-test** command to test "
                    "connectivity after setting the Authorization Code.",
                )
            result = await client.test_connection()
            return_results(result)

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
                client._oauth_handler,
                auth_type=auth_type,
                authorization_endpoint=PANORAYS_AUTHORIZATION_ENDPOINT,
                redirect_uri=redirect_uri,
                troubleshooting_redirect=True,
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
