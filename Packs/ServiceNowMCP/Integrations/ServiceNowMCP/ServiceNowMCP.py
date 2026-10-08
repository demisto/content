import demistomock as demisto
from CommonServerPython import *
from MCPApiModule import *

import asyncio

from urllib.parse import unquote


SERVICENOW_AUTH_TYPE = AuthMethods.AUTHORIZATION_CODE.value
SERVICENOW_SCOPE = "mcp_server"
COMMAND_PREFIX = "servicenow-mcp"
SERVER_NAME = "ServiceNow MCP"
DEFAULT_MCP_SERVER_NAME = "sn_mcp_server_default"


def build_servicenow_urls(instance_url: str, server_name: str) -> tuple[str, str, str]:
    """Builds the ServiceNow MCP server URL and OAuth authorization/token endpoints from the instance URL.

    Args:
        instance_url: The full ServiceNow instance URL (e.g., 'https://dev12345.service-now.com').
        server_name: The name of the MCP server on the instance.

    Returns:
        A tuple of (base_url, authorization_endpoint, token_endpoint).
    """
    instance_url = instance_url.strip().rstrip("/")
    server_name = (server_name or DEFAULT_MCP_SERVER_NAME).strip()

    base_url = f"{instance_url}/sncapps/mcp-server/mcp/{server_name}"
    authorization_endpoint = f"{instance_url}/oauth_auth.do"
    token_endpoint = f"{instance_url}/oauth_token.do"
    return base_url, authorization_endpoint, token_endpoint


def validate_required_params(instance_url: str, client_id: str, client_secret: str) -> None:
    """Validates that required parameters are present.

    Args:
        instance_url: The full ServiceNow instance URL.
        client_id: The OAuth Client ID.
        client_secret: The OAuth Client Secret.
    """
    if not instance_url:
        raise ValueError("ServiceNow Instance URL must be provided (e.g., 'https://dev12345.service-now.com').")
    if not all((client_id, client_secret)):
        raise ValueError("Client ID and Client Secret are required for OAuth authentication.")


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    client = None
    try:
        instance_url = params.get("instance_url", "")
        server_name = params.get("server_name", "")
        client_id = params.get("oauth_credentials", {}).get("identifier")
        client_secret = params.get("oauth_credentials", {}).get("password")
        auth_code = unquote(params.get("auth_code", {}).get("password") or "")
        redirect_uri = params.get("redirect_uri", "") or REDIRECT_URI
        verify: bool = not argToBoolean(params.get("insecure", False))

        validate_required_params(instance_url, client_id, client_secret)

        base_url, authorization_endpoint, token_endpoint = build_servicenow_urls(instance_url, server_name)

        client = Client(
            base_url=base_url,
            auth_type=SERVICENOW_AUTH_TYPE,
            command_prefix=COMMAND_PREFIX,
            client_id=client_id,
            client_secret=client_secret,
            auth_code=auth_code,
            token_endpoint=token_endpoint,
            scope=SERVICENOW_SCOPE,
            redirect_uri=redirect_uri,
            verify=verify,
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
                client._oauth_handler,
                auth_type=SERVICENOW_AUTH_TYPE,
                authorization_endpoint=authorization_endpoint,
                redirect_uri=redirect_uri,
                troubleshooting_redirect=True,
            )
            return_results(result)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as eg:
        root_msg = extract_root_error_message(eg)
        return_error(f"Failed to execute {command} command.\nError:\n{root_msg}")

    finally:
        if client:
            demisto.debug(f"Closing client connection for {command}")
            await client.close()


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
