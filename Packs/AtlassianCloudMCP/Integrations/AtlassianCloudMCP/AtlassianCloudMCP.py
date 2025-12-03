import demistomock as demisto
from CommonServerPython import *

import asyncio
import time
import os
import traceback
import hashlib
import json

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from typing import Any
import base64
import httpx

from urllib.parse import unquote, urlparse, urlunparse


# --- Utility Functions ---


def extract_root_error_message(exception: BaseException) -> str:
    """
    Extract the root error message from an exception, handling nested exception groups.
    """
    if isinstance(exception, BaseExceptionGroup | ExceptionGroup) and exception.exceptions:
        # Recursively check the first inner exception
        return extract_root_error_message(exception.exceptions[0])

    # Format and return the message for a regular exception
    return "".join(traceback.format_exception_only(type(exception), exception))


def url_origin(base_url: str) -> str:
    """Gets the origin (scheme and netloc) of a URL."""
    parsed = urlparse(base_url)
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def update_integration_context_oauth_flow(data: dict[str, Any]) -> None:
    """Update the integration context with the OAuth flow state."""
    integration_context = get_integration_context()
    integration_context.update(remove_empty_elements(data))
    set_integration_context(integration_context)


# --- Constants and Configuration ---

REDIRECT_URI = "http://127.0.0.1:8000/callback"
CLIENT_NAME = "Cortex AgentiX for Atlassian"
LOGO_URI = "https://www.paloaltonetworks.com/content/dam/pan/en_US/images/logos/brand/cortex-primary/Cortex-logo.png"
RESPONSE_TYPE = "code"
CODE_CHALLENGE_METHOD = "S256"
ACCESS_TOKEN_DEFAULT_DURATION_SECONDS = 1800  # Default to 30 minutes if not provided
APPLICATION_JSON_HEADERS = {"Content-Type": "application/json"}
FORM_URLENCODED_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
MCP_PROTOCOL_HEADERS = {"MCP-Protocol-Version": "2025-03-26"}
SOFTWARE_ID = "5bfad241-79aa-4a49-86df-c668f8e03e11"
SOFTWARE_VERSION = "1.0.0"
BASE_URL = "https://mcp.atlassian.com/v1/mcp"
OAUTH_AUTHORIZATION_SERVER_METADATA = {
    "issuer": "https://cf.mcp.atlassian.com",
    "authorization_endpoint": "https://mcp.atlassian.com/v1/authorize",
    "token_endpoint": "https://cf.mcp.atlassian.com/v1/token",
    "registration_endpoint": "https://cf.mcp.atlassian.com/v1/register",
    "response_types_supported": ["code"],
    "response_modes_supported": ["query"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
    "revocation_endpoint": "https://cf.mcp.atlassian.com/v1/token",
    "code_challenge_methods_supported": ["plain", "S256"],
}

CLIENT_METADATA = {
    "redirect_uris": [REDIRECT_URI],
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "client_name": CLIENT_NAME,
    "client_uri": demisto.demistoUrls().get("server", ""),
    "software_id": SOFTWARE_ID,
    "software_version": SOFTWARE_VERSION,
    "scope": [],
    "logo_uri": LOGO_URI,
}


# --- OAuth Handler Class (Consolidated OAuth Logic) ---


class OAuthHandler:
    """
    Handles OAuth 2.0 Dynamic Registration and PKCE flows.
    """

    def __init__(
        self,
        base_url: str,
        auth_code: str,
    ):
        self.base_url = base_url
        self.auth_code = auth_code

        # These will be populated from integration context after dynamic registration
        self.client_id: str = ""
        self.client_secret: str = ""
        self.token_endpoint: str = ""

    async def _discover_oauth_metadata(self, authorization_server: str) -> dict[str, Any]:
        """Discovers OAuth metadata from a given base URL."""
        error_message = f"Error discovering OAuth metadata for {authorization_server}, using default metadata."
        metadata = OAUTH_AUTHORIZATION_SERVER_METADATA
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(
                    f"{authorization_server}/.well-known/oauth-authorization-server", headers=MCP_PROTOCOL_HEADERS
                )
                if response.is_success:
                    metadata.update(response.json())
                else:
                    demisto.debug(error_message)
        except Exception:
            demisto.debug(error_message)

        return metadata

    async def _oauth_register_client(self, registration_metadata: dict[str, Any]) -> tuple[str, str]:
        """Registers a client dynamically to obtain client_id and client_secret."""
        registration_endpoint = registration_metadata["registration_endpoint"]
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.post(registration_endpoint, json=CLIENT_METADATA, headers=APPLICATION_JSON_HEADERS)
                if response.is_success:
                    client_registration = response.json()
                    client_id = client_registration.get("client_id")
                    client_secret = client_registration.get("client_secret")
                    return client_id, client_secret
                else:
                    raise DemistoException(
                        f"Failed to register OAuth client: Received status code {response.status_code}, "
                        f"and response: {response.text}"
                    )
        except Exception as e:
            demisto.error(f"Error registering OAuth client: {str(e)}")
            raise DemistoException(f"Failed to register OAuth client: {str(e)}")

    def pkce_challenge(self) -> tuple[str, str]:
        """Generate PKCE code_verifier and S256 code_challenge."""
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
        return (code_verifier, code_challenge)

    def _create_authorization_url(self, authorization_endpoint: str, client_id: str, code_challenge: str, state: str) -> str:
        """
        Constructs the authorization URL for the PKCE flow.
        """
        params: dict[str, str] = {
            "client_id": client_id,
            "response_type": RESPONSE_TYPE,
            "redirect_uri": REDIRECT_URI,
            "scope": "",
            "token_access_type": "offline",
            "state": state,
            # PKCE parameters are mandatory for Dynamic Registration flow
            "code_challenge": code_challenge,
            "code_challenge_method": CODE_CHALLENGE_METHOD,
        }

        query_string = str(httpx.QueryParams(params))
        authorization_url = f"{authorization_endpoint}?{query_string}"
        demisto.debug(f"Generated authorization URL: {authorization_url}")
        return authorization_url

    async def generate_dynamic_registration_login_url(self) -> tuple[str, dict[str, str]]:
        """
        Performs dynamic client registration and starts the authorization process.
        Returns the authorization URL and context data to save.
        """
        authorization_server = url_origin(self.base_url)

        # 1. Discover metadata from the auth server
        metadata = await self._discover_oauth_metadata(authorization_server)

        # 2. Register client dynamically
        client_id, client_secret = await self._oauth_register_client(metadata)

        # 3. Generate PKCE challenge
        code_verifier, code_challenge = self.pkce_challenge()
        authorization_endpoint = metadata.get("authorization_endpoint", "")

        # 4. Generate random state for CSRF protection
        state = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")

        # 5. Build Authorization URL
        auth_url = self._create_authorization_url(authorization_endpoint, client_id, code_challenge, state)

        context_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": code_verifier,
            "code_challenge": code_challenge,
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": metadata.get("token_endpoint"),
            "state": state,
        }
        return auth_url, context_data

    async def get_authorization_code_token(self, integration_context: dict[str, Any]) -> tuple[str, str, int]:
        """
        Obtains or refreshes an access token using Authorization Code Grant or Refresh Token (PKCE mandatory).
        """
        code_verifier = integration_context.get("code_verifier", "")
        refresh_token = integration_context.get("refresh_token", "")
        token_endpoint = integration_context.get("token_endpoint", "")
        client_id = integration_context.get("client_id", "")
        client_secret = integration_context.get("client_secret", "")

        if not token_endpoint or not client_id:
            raise DemistoException(
                "OAuth context is missing. Please run the `!atlassian-cloud-mcp-generate-login-url` command first."
            )

        payload: dict[str, Any] = {
            "client_id": client_id,
        }

        if refresh_token:
            # --- Refresh Token Flow ---
            demisto.debug("Running OAuth Refresh Token flow.")
            payload["grant_type"] = "refresh_token"
            payload["refresh_token"] = refresh_token
            payload["client_secret"] = client_secret

        elif not self.auth_code:
            # --- Missing Auth Code ---
            raise ValueError(
                "Authorization code is required for OAuth Authorization Code flow.\n"
                "To get the Authorization Code, call the !atlassian-cloud-mcp-generate-login-url command first."
            )
        else:
            # --- Authorization Code Flow (PKCE) ---
            demisto.debug("Running OAuth Authorization Code flow with PKCE.")

            payload["grant_type"] = "authorization_code"
            payload["code"] = self.auth_code
            payload["redirect_uri"] = REDIRECT_URI
            payload["code_verifier"] = code_verifier

        # Execute the token request
        try:
            async with httpx.AsyncClient(timeout=10, headers=FORM_URLENCODED_HEADERS) as client:
                response = await client.post(token_endpoint, data=payload)
                response.raise_for_status()
                result = response.json()
        except httpx.HTTPStatusError as e:
            error_details = f"HTTP Error: {e.response.status_code}. Response: {e.response.text}"
            demisto.error(error_details)
            raise DemistoException(f"Failed to obtain/refresh token. {error_details}")
        except Exception as e:
            demisto.error(f"Error during token exchange: {str(e)}")
            raise DemistoException(f"Failed to obtain/refresh token: {str(e)}")

        new_access_token = result.get("access_token")
        new_refresh_token = result.get("refresh_token")
        expires_in = result.get("expires_in", ACCESS_TOKEN_DEFAULT_DURATION_SECONDS)
        return new_access_token, new_refresh_token, expires_in


# --- Client Class (MCP and Authentication Orchestration) ---


class Client:
    """
    Client for interacting with the MCP server, specialized for
    OAuth 2.0 Dynamic Client Registration and PKCE.
    """

    def __init__(
        self,
        base_url: str,
        auth_code: str,
    ):
        self.base_url = base_url
        self.auth_code = auth_code

        # OAuth Setup using context for client details
        self._oauth_handler = OAuthHandler(
            base_url,
            auth_code,
        )

    async def _generate_oauth_headers(self) -> dict[str, str]:
        """Handles OAuth token acquisition (caching/refreshing) and returns headers."""
        integration_context = get_integration_context()
        access_token = integration_context.get("access_token")
        expires_in: float = integration_context.get("expires_in", 0)

        # 1. Check existing token
        if access_token and time.time() < expires_in:
            demisto.debug("Using existing valid access token")
            return {"Authorization": f"Bearer {access_token}"}

        # 2. Acquire new token (either via refresh or auth code)
        demisto.debug(f"Creating new access token, since {'no valid token was found' if not access_token else 'token expired'}.")

        new_token, new_refresh_token, new_expires_in = await self._oauth_handler.get_authorization_code_token(integration_context)

        # 3. Update context and return headers
        demisto.debug(f"Successfully retrieved access token, {new_expires_in=}")
        update_integration_context_oauth_flow(
            {"access_token": new_token, "expires_in": time.time() + new_expires_in, "refresh_token": new_refresh_token}
        )
        return {"Authorization": f"Bearer {new_token}"}

    async def test_connection(self, auth_test: bool = False):
        headers = await self._generate_oauth_headers()
        async with (
            streamablehttp_client(self.base_url, headers=headers) as (
                read_stream,
                write_stream,
                _,
            ),
            ClientSession(read_stream, write_stream) as session,
        ):
            # Initialize the connection
            await session.initialize()
            if auth_test:
                return CommandResults(readable_output="✅ Authentication successful.")
            else:
                return "ok"

    async def list_tools(self):
        headers = await self._generate_oauth_headers()
        async with (
            streamablehttp_client(self.base_url, headers=headers) as (
                read_stream,
                write_stream,
                _,
            ),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()

        tool_names = [tool.name for tool in tools.tools]
        readable_output = f"Available {len(tool_names)} tools:\n{tool_names}"
        demisto.debug(f"Available tools: {tool_names}")

        tools_dump = tools.model_dump(mode="json")
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="ListTools.Tools",
            outputs=tools_dump.get("tools", []),
        )

    async def call_tool(self, tool_name: str, arguments: str):
        try:
            parsed_arguments = json.loads(arguments or "{}")
        except json.JSONDecodeError:
            raise DemistoException(f"Invalid JSON provided for arguments: {arguments}")
        headers = await self._generate_oauth_headers()
        async with (
            streamablehttp_client(self.base_url, headers=headers) as (
                read_stream,
                write_stream,
                _,
            ),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            result = await session.call_tool(tool_name, parsed_arguments)

        result_dump = result.model_dump(mode="json")
        result_content = result_dump.get("content", [])
        readable_output = tableToMarkdown(f"Tool Execution '{tool_name}'{' failed' if result.isError else ''}", result_content)

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="CallTool.Tool",
            outputs=result_content,
            entry_type=EntryType.NOTE if not result.isError else EntryType.ERROR,
        )


async def generate_login_url(oauth_handler: OAuthHandler):
    """
    Generates the login URL for the OAuth Dynamic Client Registration flow.
    """
    auth_url, context_data = await oauth_handler.generate_dynamic_registration_login_url()
    update_integration_context_oauth_flow(context_data)

    result_msg = (
        "### Authorization instructions\n"
        f"1. Click on the [login URL]({auth_url}) to sign in and grant Cortex permissions for your Atlassian MCP server.\n"
        "  You will be automatically redirected to a link with the following structure:\n"
        "  ```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```\n"
        "2. Copy the **AUTH_CODE** (without the `code=` prefix) and paste it "
        "in your instance configuration under the **Authorization code** parameter.\n"
        "3. Run the **!atlassian-cloud-mcp-auth-test** command to complete the OAuth setup.\n\n"
        "**IMPORTANT NOTE**: Authentication code is time-sensitive and expires quickly.\n"
        "Please complete the authorization process promptly."
    )

    return CommandResults(readable_output=result_msg)


# --- Main Logic ---


async def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    try:
        auth_code = unquote(params.get("auth_code", {}).get("password") or "")

        client = Client(
            base_url=BASE_URL,
            auth_code=auth_code,
        )
        demisto.debug(f"Command being called is {command}")

        if command == "test-module":
            raise DemistoException(
                "\nTest module is unavailable for this integration. "
                "Please use the **!atlassian-cloud-mcp-auth-test** command to test "
                "connectivity after setting the Authorization Code.",
            )

        elif command == "list-tools":
            result = await client.list_tools()
            return_results(result)

        elif command == "call-tool":
            result = await client.call_tool(args["name"], args.get("arguments", ""))
            return_results(result)

        elif command == "atlassian-cloud-mcp-auth-test":
            result = await client.test_connection(auth_test=True)
            return_results(result)

        elif command == "atlassian-cloud-mcp-generate-login-url":
            oauth_handler = OAuthHandler(BASE_URL, auth_code)
            result = await generate_login_url(oauth_handler)
            return_results(result)

        elif command == "atlassian-cloud-mcp-auth-reset":
            set_integration_context({})
            return_results(CommandResults(readable_output="✅ Authorization was reset successfully."))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except BaseException as eg:
        root_msg = extract_root_error_message(eg)
        return_error(f"Failed to execute {command} command.\nError:\n{root_msg}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
