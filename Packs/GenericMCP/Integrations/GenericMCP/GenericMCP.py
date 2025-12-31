import demistomock as demisto
from CommonServerPython import *
from MCPApiModule import *

import asyncio


from urllib.parse import unquote


COMMAND_PREFIX = "generic-mcp"


def validate_required_params(
    base_url: str,
    auth_type: str,
    user_name: str,
    password: str,
    token: str,
    client_id: str,
    client_secret: str,
):
    """Validates that required authentication parameters are present based on authentication type."""
    if auth_type not in AuthMethods.list():
        raise ValueError(f"Unsupported authentication type: {auth_type}")
    if not base_url:
        raise ValueError("Base URL must be provided.")
    if not auth_type:
        raise ValueError("Authentication type must be specified.")
    if auth_type == AuthMethods.BASIC and not all((user_name, password)):
        raise ValueError("Username and Password are required for basic authentication.")
    if auth_type in (AuthMethods.TOKEN, AuthMethods.BEARER, AuthMethods.API_KEY, AuthMethods.RAW_TOKEN) and not token:
        raise ValueError(f"Token is required for {auth_type} authentication.")
    if auth_type in (AuthMethods.CLIENT_CREDENTIALS, AuthMethods.AUTHORIZATION_CODE) and not all({client_id, client_secret}):
        raise ValueError("Client ID, Client Secret are required for OAuth authentication.")


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    try:
        base_url = params.get("base_url", "")
        auth_type = params.get("auth_type", "")
        user_name = params.get("credentials", {}).get("identifier")
        password = params.get("credentials", {}).get("password")
        token = params.get("token", {}).get("password")
        client_id = params.get("oauth_credentials", {}).get("identifier")
        client_secret = params.get("oauth_credentials", {}).get("password")
        token_endpoint = params.get("token_endpoint", "")
        auth_code = unquote(params.get("auth_code", {}).get("password") or "")
        scope = params.get("scope", "")
        authorization_endpoint = params.get("authorization_endpoint", "")
        redirect_uri = params.get("redirect_uri", "") or REDIRECT_URI
        custom_headers = parse_custom_headers(params.get("custom_headers") or "")
        verify: bool = not argToBoolean(params.get("insecure", False))
        server_name = params.get("server_name", "")

        # Validation is run before creating the client
        validate_required_params(base_url, auth_type, user_name, password, token, client_id, client_secret)

        client = Client(
            base_url=base_url,
            auth_type=auth_type,
            command_prefix=COMMAND_PREFIX,
            user_name=user_name,
            password=password,
            token=token,
            client_id=client_id,
            client_secret=client_secret,
            auth_code=auth_code,
            token_endpoint=token_endpoint,
            scope=scope,
            custom_headers=custom_headers,
            redirect_uri=redirect_uri,
            verify=verify,
        )
        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            if auth_type in (AuthMethods.AUTHORIZATION_CODE, AuthMethods.DYNAMIC_CLIENT_REGISTRATION):
                raise DemistoException(
                    f"\nTest module is unavailable for this authentication type: {auth_type}.\n"
                    f"Please use the !{COMMAND_PREFIX}-auth-test command to test connectivity.",
                )
            result = await client.test_connection()
            return_results(result)

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
                client._oauth_handler, auth_type, authorization_endpoint, redirect_uri, troubleshooting_redirect=True
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
