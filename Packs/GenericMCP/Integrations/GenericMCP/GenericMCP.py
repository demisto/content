from enum import Enum
import demistomock as demisto
from CommonServerPython import *

import asyncio
import time
import os
import traceback
import hashlib

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from typing import Any
from base64 import b64encode
import httpx

from urllib.parse import unquote, urlparse, urlunparse

# --- Utility Functions ---


def extract_root_error_message(exception: BaseException) -> str:
    """
    Extract the root error message from an exception, handling nested exception groups.

    Args:
        exception: The exception to extract the error message from

    Returns:
        Formatted error message string from the root cause exception.
    """
    if isinstance(exception, BaseExceptionGroup | ExceptionGroup) and exception.exceptions:
        # Recursively check the first inner exception
        return extract_root_error_message(exception.exceptions[0])

    # Format and return the message for a regular exception
    return "".join(traceback.format_exception_only(type(exception), exception))


def parse_custom_headers(headers_text: str) -> dict[str, str]:
    """
    Parses custom headers provided as multiline text in the format 'HeaderName: HeaderValue'.

    Args:
        headers_text: The multiline string input from the integration parameters.

    Returns:
        A dictionary of headers {HeaderName: HeaderValue}.
    """
    if not headers_text:
        return {}

    headers: dict[str, str] = {}

    for line in headers_text.splitlines():
        clean_line = line.strip()

        if not clean_line or ":" not in clean_line:
            continue

        try:
            name, value = clean_line.split(":", 1)

            header_name = name.strip()
            header_value = value.strip()

            if header_name:
                headers[header_name] = header_value

        except ValueError:
            demisto.debug(f"Skipping malformed header line: {line}")
            continue

    demisto.debug(f"parse_custom_headers={headers}")
    return headers


def join_url(base: str, path: str) -> str:
    """Joins a base URL and a path, ensuring correct slashes."""
    parsed = urlparse(base)
    new_path = parsed.path.rstrip("/") + "/" + path.lstrip("/")
    return urlunparse(parsed._replace(path=new_path))


def url_origin_join(base_url: str, path: str = "") -> str:
    """Gets the origin (scheme and netloc) of a URL and joins a path."""
    parsed = urlparse(base_url)
    origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    return origin.rstrip("/") + ("/" + path.lstrip("/") if path else "")


def update_integration_context_oauth_flow(data: dict[str, Any]) -> None:
    """Update the integration context with the OAuth flow state."""
    integration_context = get_integration_context()
    integration_context.update(remove_empty_elements(data))
    set_integration_context(integration_context)


# --- Constants and Configuration ---

REDIRECT_URI = "https://oproxy.demisto.ninja/authcode"
CLIENT_NAME = "Cortex AgentiX"
LOGO_URI = "https://www.paloaltonetworks.com/content/dam/pan/en_US/images/logos/brand/cortex-primary/Cortex-logo.png"
RESPONSE_TYPE = "code"
CODE_CHALLENGE_METHOD = "S256"
ACCESS_TOKEN_DEFAULT_DURATION_SECONDS = 1800  # Default to 30 minutes if not provided
APPLICATION_JSON_HEADERS = {"Content-Type": "application/json"}
FORM_URLENCODED_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
MCP_PROTOCOL_HEADERS = {"MCP-Protocol-Version": "2025-03-26"}
SOFTWARE_ID = "5bfad241-79aa-4a49-86df-c668f8e03e11"
SOFTWARE_VERSION = "1.0.0"


class AuthMethods(str, Enum):
    BASIC = "Basic"
    TOKEN = "Token"
    BEARER = "Bearer"
    API_KEY = "Api-Key"
    RAW_TOKEN = "RawToken"
    NO_AUTHORIZATION = "No Authorization"
    AUTHORIZATION_CODE = "OAuth 2.0 Authorization Code"
    CLIENT_CREDENTIALS = "OAuth 2.0 Client Credentials"
    DYNAMIC_CLIENT_REGISTRATION = "OAuth 2.0 Dynamic Client Registration"

    @classmethod
    def list(cls) -> list[str]:
        """
        Returns a list of all string values defined in the Enum.
        """
        return [member.value for member in cls]


def get_client_metadata(redirect_uri: str) -> dict[str, Any]:
    """Returns metadata used for OAuth Dynamic Client Registration."""
    return {
        "redirect_uris": [redirect_uri],
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
    Handles OAuth 2.0 flows, discovery, and client registration.
    Uses httpx.AsyncClient for token operations.
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        token_endpoint: str,
        scope: str,
        auth_code: str,
        redirect_uri: str,
        verify: bool,
    ):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_endpoint = token_endpoint
        self.scope = scope
        self.auth_code = auth_code
        self.redirect_uri = redirect_uri
        self.verify = verify

    async def _discover_oauth_protected_resource_metadata(self) -> str:
        """
        Enhanced metadata discovery for OAuth protected resources.
        Returns the authorization server URL.
        """
        origin_base_url = url_origin_join(self.base_url)
        authorization_servers = origin_base_url
        error_message = (
            f"Error discovering OAuth protected resource metadata for {origin_base_url}, falling back to default base URL"
        )
        try:
            async with httpx.AsyncClient(timeout=5, verify=self.verify) as client:
                response = await client.get(
                    f"{origin_base_url}/.well-known/oauth-protected-resource", headers=MCP_PROTOCOL_HEADERS
                )
                if response.is_success:
                    metadata = response.json()
                    authorization_servers = (
                        metadata.get("authorization_servers")[0] if metadata.get("authorization_servers") else origin_base_url
                    )
                else:
                    demisto.debug(error_message)
        except Exception:
            demisto.debug(error_message)

        return authorization_servers

    async def _discover_oauth_metadata(self, base_url: str) -> dict[str, Any]:
        """Discovers OAuth metadata from a given base URL."""
        metadata = {
            "registration_endpoint": url_origin_join(base_url, "register"),
            "token_endpoint": url_origin_join(base_url, "token"),
            "response_types_supported": [RESPONSE_TYPE],
            "code_challenge_methods_supported": [CODE_CHALLENGE_METHOD],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "authorization_endpoint": url_origin_join(base_url, "oauth2/authorize"),
        }
        error_message = f"Error discovering OAuth metadata for {base_url}, using default metadata."
        try:
            async with httpx.AsyncClient(timeout=5, verify=self.verify) as client:
                response = await client.get(f"{base_url}/.well-known/oauth-authorization-server", headers=MCP_PROTOCOL_HEADERS)
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
            async with httpx.AsyncClient(timeout=5, verify=self.verify) as client:
                response = await client.post(
                    registration_endpoint, json=get_client_metadata(self.redirect_uri), headers=APPLICATION_JSON_HEADERS
                )
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

    def _create_authorization_url(
        self, authorization_endpoint: str, client_id: str, scope: str, code_challenge: str = "", state: str = ""
    ) -> str:
        """
        Constructs the authorization URL manually (replaces client.create_authorization_url).
        Handles both PKCE (dynamic registration) and standard flow.
        """
        params: dict[str, str] = {
            "client_id": client_id,
            "response_type": RESPONSE_TYPE,
            "redirect_uri": self.redirect_uri,
            "scope": scope,
            "token_access_type": "offline",
        }

        if code_challenge:
            # Add PKCE parameters for Dynamic Registration flow
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = CODE_CHALLENGE_METHOD
        if state:
            # Add optional state parameter for CSRF protection
            params["state"] = state

        query_string = str(httpx.QueryParams(params))
        authorization_url = f"{authorization_endpoint}?{query_string}"
        demisto.debug(f"Generated authorization URL: {authorization_url}")
        return authorization_url

    async def generate_dynamic_registration_login_url(self) -> tuple[str, dict[str, str]]:
        """
        Performs dynamic client registration and starts the authorization process.
        Returns the authorization URL and context data to save.
        """
        # 1. Discover authorization server
        authorization_server = await self._discover_oauth_protected_resource_metadata()

        # 2. Discover metadata from the auth server
        metadata = await self._discover_oauth_metadata(authorization_server)

        # 3. Register client dynamically
        client_id, client_secret = await self._oauth_register_client(metadata)

        # 4. Generate PKCE challenge
        code_verifier, code_challenge = self.pkce_challenge()
        authorization_endpoint = metadata.get("authorization_endpoint", "")

        # 5. Generate random state for CSRF protection
        state = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")

        # 6. Build Authorization URL using the internal helper
        auth_url = self._create_authorization_url(authorization_endpoint, client_id, self.scope, code_challenge, state)

        context_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": code_verifier,
            "code_challenge": code_challenge,
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": metadata.get("token_endpoint"),
            "redirect_uri": self.redirect_uri,
            "state": state,
        }
        return auth_url, context_data

    def generate_authorization_code_login_url(self, authorization_endpoint: str) -> str:
        """Generates the login URL for the standard Authorization Code flow."""
        auth_endpoint = authorization_endpoint or url_origin_join(self.base_url, "oauth2/authorize")

        auth_url = self._create_authorization_url(auth_endpoint, self.client_id, self.scope)
        return auth_url

    async def get_client_credentials_token(self) -> tuple[str, int]:
        """Obtains an access token using Client Credentials Grant."""
        demisto.debug("Running Client Credentials Grant flow")
        token_endpoint = self.token_endpoint if self.token_endpoint else url_origin_join(self.base_url, "oauth2/token")

        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scope,
        }
        async with httpx.AsyncClient(timeout=10, verify=self.verify, headers=FORM_URLENCODED_HEADERS) as client:
            response = await client.post(token_endpoint, data=payload)
            response.raise_for_status()
            result = response.json()

        token = result.get("access_token", "")
        expires_in = result.get("expires_in", ACCESS_TOKEN_DEFAULT_DURATION_SECONDS)
        return token, expires_in

    async def get_authorization_code_token(self, refresh_token: str, code_verifier: str = "") -> tuple[str, str, int]:
        """
        Obtains or refreshes an access token using Authorization Code Grant or Refresh Token.
        Dynamically handles client_secret vs. code_verifier (PKCE).
        """
        token_endpoint = self.token_endpoint if self.token_endpoint else url_origin_join(self.base_url, "oauth2/token")
        payload: dict[str, Any] = {
            "client_id": self.client_id,
        }

        if refresh_token:
            # --- Refresh Token Flow ---
            demisto.debug("Running OAuth Refresh Token flow.")
            payload["grant_type"] = "refresh_token"
            payload["refresh_token"] = refresh_token
            # Client Secret is required for Refresh Token flow for confidential clients
            if self.client_secret:
                payload["client_secret"] = self.client_secret

        elif not self.auth_code:
            # --- Missing Auth Code ---
            raise ValueError(
                "Authorization code is required for OAuth Authorization Code flow.\n"
                "To get the Authorization Code, call the !generic-mcp-generate-login-url command first."
            )
        else:
            # --- Authorization Code Flow ---
            demisto.debug("Running OAuth Authorization Code flow.")

            payload["grant_type"] = "authorization_code"
            payload["code"] = self.auth_code
            payload["redirect_uri"] = self.redirect_uri
            if code_verifier:
                # PKCE flow relies on code_verifier, client_secret is typically omitted/optional
                payload["code_verifier"] = code_verifier
            elif self.client_secret:
                # Standard confidential client flow
                payload["client_secret"] = self.client_secret

        # Execute the token request
        try:
            async with httpx.AsyncClient(timeout=10, headers=FORM_URLENCODED_HEADERS, verify=self.verify) as client:
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
    Client for interacting with the MCP server, responsible for:
    1. Orchestrating the authentication flows.
    2. Handling MCP protocol commands (test, list_tools, call_tool).
    """

    def __init__(
        self,
        base_url: str,
        auth_type: str,
        user_name: str,
        password: str,
        token: str,
        client_id: str,
        client_secret: str,
        auth_code: str,
        token_endpoint: str,
        scope: str,
        custom_headers: dict[str, str],
        redirect_uri: str,
        verify: bool,
    ):
        self.base_url = base_url
        self.auth_type = auth_type
        self.user_name = user_name
        self.password = password
        self.token = token
        self.custom_headers = custom_headers
        self.verify = verify

        # OAuth Setup
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_code = auth_code
        self.token_endpoint = token_endpoint
        self.scope = scope
        self._oauth_handler = OAuthHandler(
            base_url, client_id, client_secret, token_endpoint, scope, auth_code, redirect_uri, verify
        )
        self._headers_cache: dict[Any, Any] = {}  # Cache for resolved headers

    async def _resolve_headers(self) -> dict[Any, Any]:
        """
        Generates and caches the necessary Authorization headers based on auth_type.
        Handles token expiration and refreshing for OAuth flows.
        """
        # Return cached headers if available (OAuth token refresh is handled internally)
        if self._headers_cache:
            return self._headers_cache | self.custom_headers

        headers = {}

        if self.auth_type == AuthMethods.NO_AUTHORIZATION:
            demisto.debug("Connecting without Authorization")

        elif self.auth_type == AuthMethods.BASIC:
            demisto.debug(f"Authenticating with Basic Authentication, username: {self.user_name}")
            auth_credentials = f"{self.user_name}:{self.password}"
            encoded_credentials = b64encode(auth_credentials.encode()).decode("utf-8")
            headers = {"Authorization": f"Basic {encoded_credentials}"}

        elif self.auth_type in (AuthMethods.BEARER, AuthMethods.TOKEN, AuthMethods.API_KEY, AuthMethods.RAW_TOKEN):
            demisto.debug(f"Authenticating with {self.auth_type}")
            if self.auth_type == AuthMethods.BEARER:
                headers = {"Authorization": f"Bearer {self.token}"}
            elif self.auth_type == AuthMethods.TOKEN:
                headers = {"Authorization": f"Token {self.token}"}
            elif self.auth_type == AuthMethods.API_KEY:
                headers = {"api-key": self.token}
            elif self.auth_type == AuthMethods.RAW_TOKEN:
                headers = {"Authorization": self.token}

        elif self.auth_type in (
            AuthMethods.CLIENT_CREDENTIALS,
            AuthMethods.AUTHORIZATION_CODE,
            AuthMethods.DYNAMIC_CLIENT_REGISTRATION,
        ):
            headers = await self._generate_oauth_headers()

        self._headers_cache = headers
        return headers | self.custom_headers

    async def _generate_oauth_headers(self) -> dict[str, str]:
        """Handles OAuth token acquisition (caching/refreshing) and returns headers."""
        integration_context = get_integration_context()
        access_token = integration_context.get("access_token")
        expires_in: float = integration_context.get("expires_in", 0)

        # 1. Check existing token
        if access_token and time.time() < expires_in:
            demisto.debug("Using existing valid access token")
            return {"Authorization": f"Bearer {access_token}"}

        # 2. Acquire new token
        demisto.debug(f"Creating new access token, since {'no valid token was found' if not access_token else 'token expired'}.")

        new_token = ""
        new_refresh_token = ""
        new_expires_in = 0

        if self.auth_type == AuthMethods.CLIENT_CREDENTIALS:
            new_token, new_expires_in = await self._oauth_handler.get_client_credentials_token()

        elif self.auth_type in (AuthMethods.AUTHORIZATION_CODE, AuthMethods.DYNAMIC_CLIENT_REGISTRATION):
            # Update OAuth handler details from context for Dynamic Registration flow
            if self.auth_type == AuthMethods.DYNAMIC_CLIENT_REGISTRATION:
                self._oauth_handler.client_id = integration_context.get("client_id", "")
                self._oauth_handler.client_secret = integration_context.get("client_secret", "")
                self._oauth_handler.token_endpoint = integration_context.get("token_endpoint", "")
                self._oauth_handler.redirect_uri = integration_context.get("redirect_uri", "")
                code_verifier = integration_context.get("code_verifier", "")
            else:
                code_verifier = ""
            refresh_token = integration_context.get("refresh_token", "")

            new_token, new_refresh_token, new_expires_in = await self._oauth_handler.get_authorization_code_token(
                refresh_token, code_verifier
            )

        # 3. Update context and return headers
        demisto.debug(f"Successfully retrieved access token for {self.auth_type}, {new_expires_in=}")
        update_integration_context_oauth_flow(
            {"access_token": new_token, "expires_in": time.time() + new_expires_in, "refresh_token": new_refresh_token}
        )
        return {"Authorization": f"Bearer {new_token}"}

    async def test_connection(self, auth_test: bool = False):
        headers = await self._resolve_headers()
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
        headers = await self._resolve_headers()
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
        headers = await self._resolve_headers()
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


async def generate_login_url(oauth_handler: OAuthHandler, auth_type: str, authorization_endpoint: str):
    """
    Generates the login URL for the OAuth Authorization Code flow.
    This function handles both static and dynamic registration flows.
    """
    if auth_type not in (AuthMethods.AUTHORIZATION_CODE, AuthMethods.DYNAMIC_CLIENT_REGISTRATION):
        raise ValueError(
            f"To generate a login URL, 'auth_type' must be a valid OAuth flow type. Invalid type received: {auth_type}"
        )

    auth_url = ""
    if auth_type == AuthMethods.AUTHORIZATION_CODE:
        auth_url = oauth_handler.generate_authorization_code_login_url(authorization_endpoint)

    if auth_type == AuthMethods.DYNAMIC_CLIENT_REGISTRATION:
        auth_url, context_data = await oauth_handler.generate_dynamic_registration_login_url()
        update_integration_context_oauth_flow(context_data)

    result_msg = (
        "### Authorization instructions\n"
        f"1. Click on the [login URL]({auth_url}) to sign in and grant Cortex permissions for your MCP server.\n"
        "  You will be automatically redirected to a link with the following structure:\n"
        "  ```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```\n"
        "2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter) and paste it "
        "in your instance configuration under the **Authorization code** parameter.\n"
        "3. Run the **!generic-mcp-auth-test** command to complete the OAuth setup.\n\n"
        "**IMPORTANT NOTE**: Authentication code is time-sensitive and expires quickly.\n"
        "Please complete the authorization process promptly."
    )

    return CommandResults(readable_output=result_msg)


# --- Main Logic ---


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

        # Validation is run before creating the client
        validate_required_params(base_url, auth_type, user_name, password, token, client_id, client_secret)

        client = Client(
            base_url=base_url,
            auth_type=auth_type,
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
                    "Please use the !generic-mcp-auth-test command to test connectivity.",
                )
            result = await client.test_connection()
            return_results(result)

        elif command == "list-tools":
            result = await client.list_tools()
            return_results(result)

        elif command == "call-tool":
            result = await client.call_tool(args.get("name"), args.get("arguments", ""))
            return_results(result)

        elif command == "generic-mcp-auth-test":
            result = await client.test_connection(auth_test=True)
            return_results(result)

        elif command == "generic-mcp-generate-login-url":
            oauth_handler = OAuthHandler(
                base_url, client_id, client_secret, token_endpoint, scope, auth_code, redirect_uri, verify
            )
            result = await generate_login_url(oauth_handler, auth_type, authorization_endpoint)
            return_results(result)

        elif command == "generic-mcp-auth-reset":
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
