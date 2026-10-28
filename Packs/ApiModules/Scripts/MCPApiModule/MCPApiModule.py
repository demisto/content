import demistomock as demisto  # pylint: disable=W9005
from CommonServerPython import *

from contextlib import asynccontextmanager
from enum import Enum

import time
import os
import traceback
import hashlib

from mcp.client.auth.exceptions import OAuthFlowError
from mcp.client.auth.utils import validate_authorization_response_iss, validate_metadata_issuer

# Aliased: this module defines its own `Client`, which orchestrates authentication on top of
# the SDK's MCP client.
from mcp.client.client import Client as MCPClient
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthMetadata
from pydantic import ValidationError
from typing import Any
import base64
from base64 import b64encode

# mcp 2.0 replaced its httpx dependency with httpx2. The two libraries are not
# interchangeable at runtime, so the client handed to streamable_http_client must be an
# httpx2 client. httpx2 is API-compatible with httpx, so it is used throughout.
import httpx2

from urllib.parse import parse_qsl, unquote, urlparse, urlunparse

# --- Utility Functions ---

TOKEN_EXPIRY_BUFFER = 60  # seconds


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

        if not clean_line:
            continue

        try:
            name, value = clean_line.split(":", 1)

            header_name = name.strip()
            header_value = value.strip()

            if header_name:
                headers[header_name] = header_value

        except ValueError:
            raise ValueError(f"Invalid header line format: {line}")

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


def generate_state() -> str:
    """
    Generate a random state parameter for OAuth flows (CSRF protection).

    Returns:
        A URL-safe base64-encoded random string without padding.
    """
    return base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")


def update_integration_context_oauth_flow(data: dict[str, Any], override: bool = False) -> None:
    """Update the integration context with the OAuth flow state."""
    if override:
        integration_context = data
    else:
        integration_context = get_integration_context()
        integration_context.update(remove_empty_elements(data))
    set_integration_context(integration_context)


def parse_authorization_response(auth_code_input: str) -> dict[str, str]:
    """
    Parse the value pasted into the 'Authorization code' parameter.

    Accepts either the full redirect URL the authorization server sent the user to, or - for
    backwards compatibility with instances configured before this was supported - a bare
    authorization code.

    Parsing the full URL is what makes `state` (CSRF) and `iss` (RFC 9207 mix-up) validation
    possible: those values only ever reach us through the redirect, and the previous flow
    instructed users to discard everything except the code.

    Args:
        auth_code_input: The raw user-supplied value (full redirect URL or bare code).

    Returns:
        A dict with the 'code' key, plus 'state' and 'iss' when they were present in a URL, and
        'is_full_url' recording which form was supplied. A bare code yields only 'code' and
        'is_full_url'. The flag matters because an absent `iss` means something different in
        each case: the server omitted it, versus the user never pasted it.
    """
    value = (auth_code_input or "").strip()
    if not value:
        return {}

    # A bare authorization code contains no query string. Treat anything with a query
    # delimiter or an explicit code= pair as a redirect URL. A bare value is url-decoded here
    # because that is what callers have always done to it before this function existed.
    if "?" not in value and "code=" not in value:
        return {"code": unquote(value), "is_full_url": ""}

    # For a full URL, parse_qsl performs the decoding. Decoding the URL beforehand would decode
    # each value a second time and silently corrupt any code containing '%2F' or '%2B'.
    query = urlparse(value).query or value.partition("?")[2] or value
    params = dict(parse_qsl(query))

    parsed: dict[str, str] = {"is_full_url": "true"}
    parsed.update({key: params[key] for key in ("code", "state", "iss") if params.get(key)})
    if not parsed.get("code"):
        raise DemistoException(
            "Could not find an authorization code in the provided value. Paste either the full "
            "redirect URL you were sent to after signing in, or just the authorization code."
        )
    return parsed


def build_oauth_metadata(metadata: dict[str, Any]) -> OAuthMetadata | None:
    """
    Parse discovered OAuth metadata into the SDK model used by the spec validators.

    Args:
        metadata: The raw authorization server metadata.

    Returns:
        The parsed model, or None if the metadata is absent or does not satisfy the schema.
    """
    if not metadata or not metadata.get("issuer"):
        return None
    try:
        return OAuthMetadata.model_validate(metadata)
    except ValidationError as error:
        # Logged at error level rather than debug: an unparseable document silently disables
        # the RFC 9207 issuer check, so it should be visible when diagnosing an auth failure.
        demisto.error(f"Authorization server metadata did not match the OAuth schema: {error}")
        return None


def validate_state(received_state: str, expected_state: str, is_full_url: bool) -> None:
    """
    Validate the `state` authorization-response parameter (CSRF protection, RFC 6749 section 10.12).

    This is handled here rather than by the SDK because the SDK's OAuth provider owns `state`
    internally, whereas this integration hands the user a login URL and receives the response
    back through configuration on a later execution.

    An absent `state` is only tolerated when the user supplied a bare authorization code, which
    carries no response parameters at all. When a full redirect URL was supplied the parameters
    were available, so a missing `state` means it was removed and the check must fail - otherwise
    stripping one parameter would be enough to disable CSRF protection.

    Args:
        received_state: The state returned on the authorization response.
        expected_state: The state recorded when the login URL was generated.
        is_full_url: Whether the user supplied the full redirect URL.

    Raises:
        DemistoException: If the two do not match, or `state` is missing from a full redirect URL.
    """
    if not expected_state:
        demisto.debug("Skipping OAuth state validation: no state was stored for this flow.")
        return
    if not received_state:
        if is_full_url:
            raise DemistoException(
                "OAuth state missing: the pasted redirect URL does not contain the 'state' parameter "
                "that was sent with the login request. Re-run the generate-login-url command and paste "
                "the complete URL. If this repeats, the authorization response may have been tampered with."
            )
        demisto.debug(
            "Skipping OAuth state validation: only an authorization code was provided, so the "
            "authorization response parameters are unavailable."
        )
        return
    if received_state != expected_state:
        raise DemistoException(
            "OAuth state mismatch: the authorization response does not match the login request. "
            "Re-run the generate-login-url command and complete the sign-in again. If this repeats, "
            "the authorization response may have been tampered with."
        )
    demisto.debug("Validated OAuth state (CSRF protection).")


def validate_authorization_response(received: dict[str, str], integration_context: dict[str, Any]) -> None:
    """
    Validate the authorization response against the values recorded when the login URL was built.

    Two independent checks:
      - `state` (CSRF): proves this response belongs to a flow we started.
      - `iss` (RFC 9207 / SEP-2468): proves which authorization server issued the code, defending
        against mix-up attacks when a client can talk to more than one authorization server.

    The `iss` check is delegated to the MCP SDK so the comparison matches the reference client:
    a mismatch is always rejected, and an absent `iss` is rejected when the authorization server
    advertised `authorization_response_iss_parameter_supported`.

    That second rule is only applied when the user supplied the full redirect URL. The SDK reads
    the redirect itself, so for it a missing `iss` can only mean the server omitted it. Here the
    value is transcribed by hand, so a missing `iss` far more likely means the user pasted only
    the code - the long-standing instruction. Enforcing the rule in that case would reject every
    instance configured before full-URL pasting was supported.

    Args:
        received: Values parsed from the authorization response.
        integration_context: The stored OAuth flow context.

    Raises:
        DemistoException: If the response contradicts the recorded flow.
    """
    is_full_url = bool(received.get("is_full_url"))
    validate_state(received.get("state", ""), integration_context.get("state", ""), is_full_url)

    received_iss = received.get("iss")
    if not received_iss and not is_full_url:
        # Deprecated input form. Surfaced as a warning rather than a debug line because the
        # protection is silently unavailable, and because this form is intended to stop being
        # accepted in a future major version.
        demisto.info(
            "Only an authorization code was provided, so CSRF (state) and authorization server "
            "mix-up (iss) protections could not be verified. Paste the full redirect URL from "
            "your browser into the Redirect URL or Authorization Code parameter to enable them. Support for "
            "bare authorization codes is deprecated and will be removed in a future version."
        )
        return

    oauth_metadata = build_oauth_metadata(integration_context.get("oauth_metadata", {}))
    try:
        validate_authorization_response_iss(received_iss, oauth_metadata)
    except OAuthFlowError as error:
        raise DemistoException(
            f"OAuth issuer validation failed: {error}. Re-run the generate-login-url command and "
            "complete the sign-in again. If this repeats, the authorization response may have been "
            "tampered with."
        )
    demisto.debug("Validated OAuth issuer (RFC 9207 mix-up protection).")


# --- Constants and Configuration ---

REDIRECT_URI = "https://oproxy.demisto.ninja/authcode"
CLIENT_NAME = "Palo Alto Networks"
LOGO_URI = "https://www.paloaltonetworks.com/content/dam/pan/en_US/images/logos/brand/cortex-primary/Cortex-logo.png"
RESPONSE_TYPE = "code"
CODE_CHALLENGE_METHOD = "S256"
ACCESS_TOKEN_DEFAULT_DURATION_SECONDS = 1800  # Default to 30 minutes if not provided
APPLICATION_JSON_HEADERS = {"Content-Type": "application/json"}
FORM_URLENCODED_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}

# Sent ONLY on the OAuth discovery requests (.well-known/*), never on the MCP session.
# The session's protocol version is negotiated by the SDK inside the JSON-RPC body and is
# unrelated to this value. Do not reuse this constant on session requests: a 2026-07-28
# header declares the stateless core, and a server will reject it (-32020) if the request
# is a legacy `initialize` handshake.
OAUTH_DISCOVERY_HEADERS = {"MCP-Protocol-Version": "2026-07-28"}
SOFTWARE_ID = "5bfad241-79aa-4a49-86df-c668f8e03e11"

# OAuth Dynamic Client Registration `application_type` values (SEP-837 / RFC 7591).
APPLICATION_TYPE_WEB = "web"
APPLICATION_TYPE_NATIVE = "native"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
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
    def list(cls) -> list[str]:  # pylint: disable=W9014
        """
        Returns a list of all string values defined in the Enum.
        """
        return [member.value for member in cls]


def resolve_application_type(redirect_uri: str) -> str:
    """
    Determine the OAuth Dynamic Client Registration `application_type` for a redirect URI.

    Required by the MCP 2026-07-28 spec (SEP-837). Per RFC 8252, loopback redirects
    (http://127.0.0.1, http://[::1], http://localhost) and custom URI schemes identify a
    native client; a public https redirect identifies a web client.

    Args:

        redirect_uri: The redirect URI the client will register.

    Returns:
        Either APPLICATION_TYPE_NATIVE or APPLICATION_TYPE_WEB.
    """
    parsed = urlparse(redirect_uri)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    if scheme not in ("http", "https"):
        # A custom scheme (e.g. com.example.app:/oauth) is only used by native clients.
        return APPLICATION_TYPE_NATIVE
    if hostname in LOOPBACK_HOSTS:
        return APPLICATION_TYPE_NATIVE
    return APPLICATION_TYPE_WEB


def get_client_metadata(redirect_uri: str) -> dict[str, Any]:
    """Returns metadata used for OAuth Dynamic Client Registration."""
    return {
        "redirect_uris": [redirect_uri],
        "application_type": resolve_application_type(redirect_uri),
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
    Uses httpx2.AsyncClient for token operations.
    """

    def __init__(
        self,
        base_url: str,
        command_prefix,
        client_id: str = "",
        client_secret: str = "",
        token_endpoint: str = "",
        scope: str = "",
        auth_code: str = "",
        redirect_uri: str = REDIRECT_URI,
        verify: bool = True,
    ):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_endpoint = token_endpoint
        self.scope = scope
        self.redirect_uri = redirect_uri
        self.verify = verify
        self.session = httpx2.AsyncClient(timeout=5, verify=verify)
        self.command_prefix = command_prefix

        # The user may paste the full redirect URL (preferred - carries `state` and `iss`) or a
        # bare authorization code (legacy). Keep both the code and the response parameters.
        self.authorization_response = parse_authorization_response(auth_code)
        self.auth_code = self.authorization_response.get("code", "")

    async def close(self):
        if self.session:
            demisto.debug(f"Closing OAuth session for {self.command_prefix}")
            await self.session.aclose()

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
            response = await self.session.get(
                f"{origin_base_url}/.well-known/oauth-protected-resource", headers=OAUTH_DISCOVERY_HEADERS
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
            response = await self.session.get(
                f"{base_url}/.well-known/oauth-authorization-server", headers=OAUTH_DISCOVERY_HEADERS
            )
            if response.is_success:
                metadata.update(response.json())
            else:
                demisto.debug(error_message)
        except Exception:
            demisto.debug(error_message)

        # Anchor the issuer to the URL it was discovered from (RFC 8414 section 3.3 / SEP-2468).
        # Without this, the later `iss` check would compare a server's self-declaration against
        # the same self-declaration and prove nothing. Delegated to the SDK so the comparison
        # matches the reference client exactly (simple string comparison, no URL normalization).
        #
        # Metadata that is absent or unparseable deliberately leaves no issuer recorded: the
        # `iss` check then relies on whether the server advertised support, rather than on an
        # issuer value we invented.
        if parsed_metadata := build_oauth_metadata(metadata):
            try:
                validate_metadata_issuer(parsed_metadata, url_origin_join(base_url))
            except OAuthFlowError as error:
                raise DemistoException(
                    f"OAuth authorization server metadata is inconsistent: {error}. RFC 8414 requires the "
                    "metadata issuer to match the URL it was served from. Refusing to continue, as the "
                    "metadata may have been tampered with."
                )

        return metadata

    async def _oauth_register_client(self, registration_metadata: dict[str, Any]) -> tuple[str, str]:
        """Registers a client dynamically to obtain client_id and client_secret."""
        registration_endpoint = registration_metadata["registration_endpoint"]
        try:
            response = await self.session.post(
                registration_endpoint, json=get_client_metadata(self.redirect_uri), headers=APPLICATION_JSON_HEADERS
            )
            if response.is_success:
                client_registration = response.json()
                client_id = client_registration.get("client_id")
                client_secret = client_registration.get("client_secret")
                return client_id, client_secret
            else:
                raise DemistoException(
                    f"Failed to register OAuth client: Received status code {response.status_code}, and response: {response.text}"
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

        query_string = str(httpx2.QueryParams(params))
        authorization_url = f"{authorization_endpoint}?{query_string}"
        demisto.debug(f"Generated authorization URL: {authorization_url}")
        return authorization_url

    async def generate_dynamic_registration_login_url(self) -> tuple[str, dict[str, Any]]:
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
        state = generate_state()

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
            # Recorded so the `iss` on the authorization response can be validated (RFC 9207).
            # The whole metadata document is kept, not just the issuer, because the validator
            # also needs `authorization_response_iss_parameter_supported` to decide whether an
            # absent `iss` is acceptable.
            "oauth_metadata": metadata,
        }
        return auth_url, context_data

    def generate_authorization_code_login_url(self, authorization_endpoint: str) -> tuple[str, dict[str, Any]]:
        """
        Generates the login URL for the standard Authorization Code flow.

        Returns the authorization URL and the context data to save. The context data carries the
        `state` so it can be validated when the authorization response comes back; previously it
        was generated, sent, and then discarded, which left the CSRF check unenforceable.
        """
        auth_endpoint = authorization_endpoint or url_origin_join(self.base_url, "oauth2/authorize")
        state = generate_state()
        auth_url = self._create_authorization_url(auth_endpoint, self.client_id, self.scope, state=state)
        context_data = {
            "authorization_endpoint": auth_endpoint,
            "redirect_uri": self.redirect_uri,
            "state": state,
            # This flow performs no RFC 8414 discovery (the endpoints are constructed from the
            # instance URL), so the only issuer identity available is the authorization
            # endpoint's own origin. Recorded in metadata shape so the same RFC 9207 validator
            # handles both flows. No `authorization_response_iss_parameter_supported` is set,
            # so an absent `iss` is tolerated here - the server never advertised otherwise.
            "oauth_metadata": {
                "issuer": url_origin_join(auth_endpoint),
                "authorization_endpoint": auth_endpoint,
                "token_endpoint": self.token_endpoint or url_origin_join(self.base_url, "oauth2/token"),
            },
        }
        return auth_url, context_data

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

        response = await self.session.post(token_endpoint, data=payload, headers=FORM_URLENCODED_HEADERS)
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
                f"To get the Authorization Code, call the !{self.command_prefix}-generate-login-url command first."
            )
        else:
            # --- Authorization Code Flow ---
            demisto.debug("Running OAuth Authorization Code flow.")

            # Verify the authorization response before redeeming the code. Only applies here:
            # a refresh token is not an authorization response and carries no state/iss.
            validate_authorization_response(self.authorization_response, get_integration_context())

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
            response = await self.session.post(token_endpoint, data=payload, headers=FORM_URLENCODED_HEADERS)
            response.raise_for_status()
            result = response.json()
        except httpx2.HTTPStatusError as e:
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


def _flatten_nullable_type(schema: dict[str, Any]) -> dict[str, Any]:
    """Return the schema with a list-valued JSON Schema "type" replaced by the single real type it names, or left out.

    ["string", "null"] becomes "string", because "null" only marks the value as optional. A list that names no real
    type (["null"]) or several (["string", "number"]) loses its "type", since picking one would be a guess. The
    server stores a field without a type as unknown. Any other form (a plain string, anyOf, oneOf) is returned as is.
    The given schema is never modified.
    """
    declared = schema.get("type")
    if not isinstance(declared, list):
        return schema
    real_types = {entry for entry in declared if isinstance(entry, str) and entry != "null"}
    single_type = next(iter(real_types)) if len(real_types) == 1 else None
    return {key: single_type if key == "type" else value for key, value in schema.items() if key != "type" or single_type}


def _normalize_property(name: str, prop: Any, is_output: bool) -> Any:
    """Return the property with a readable type and, for an output property, a description. The input is not modified."""
    if not isinstance(prop, dict):
        return prop
    prop = _flatten_nullable_type(prop)
    if is_output and not prop.get("description"):
        title = prop.get("title")
        prop = {**prop, "description": title if isinstance(title, str) and title else name}
    return prop


def _normalize_schema(schema: dict[str, Any], is_output: bool) -> dict[str, Any]:
    """Return the schema with its own type and each of its direct properties normalized. The input is not modified."""
    schema = _flatten_nullable_type(schema)
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return schema
    return {**schema, "properties": {name: _normalize_property(name, prop, is_output) for name, prop in properties.items()}}


# Workaround for MCP servers whose tool schemas are valid but not readable by the platform's tool discovery.
# The platform-side fix is tracked in CRTX-289860. Once it ships, this normalization becomes redundant and should be removed.
def normalize_tool_schemas(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the list-tools output in a form the platform's MCP tool discovery can read. The input is not modified.

    The platform reads every property "type" as a single string, so one nullable type such as ["string", "null"]
    makes it drop the whole server's tool list. It also rejects an output property that has no description.
    Only these two cases are changed; schemas the platform already reads are returned as they are.
    """
    return [
        {
            **tool,
            **{
                key: _normalize_schema(tool[key], is_output=key == "outputSchema")
                for key in ("inputSchema", "outputSchema")
                if isinstance(tool.get(key), dict)
            },
        }
        for tool in tools
    ]


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
        command_prefix: str = "",
        user_name: str = "",
        password: str = "",
        token: str = "",
        client_id: str = "",
        client_secret: str = "",
        auth_code: str = "",
        token_endpoint: str = "",
        scope: str = "",
        custom_headers: dict[str, str] | None = None,
        redirect_uri: str = "",
        verify: bool = True,
    ):
        self.base_url = base_url
        self.auth_type = auth_type
        self.user_name = user_name
        self.password = password
        self.token = token
        self.custom_headers = custom_headers or {}
        self.verify = verify

        # OAuth Setup
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_code = auth_code
        self.token_endpoint = token_endpoint
        self.scope = scope
        self._oauth_handler = OAuthHandler(
            base_url, command_prefix, client_id, client_secret, token_endpoint, scope, auth_code, redirect_uri, verify
        )
        self._headers_cache: dict[Any, Any] = {}  # Cache for resolved headers

    async def close(self):
        if self._oauth_handler:
            await self._oauth_handler.close()

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
        if access_token and time.time() < (expires_in - TOKEN_EXPIRY_BUFFER):
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

    @asynccontextmanager
    async def _get_session(self):
        """
        Creates and initializes an async context manager for an MCP client session.

        Establishes a streamable HTTP connection to the MCP server and connects a client. The
        connection is negotiated with `mode="auto"`: the client first probes `server/discover`
        to use the stateless per-request protocol introduced in MCP 2026-07-28 (SEP-2575,
        SEP-2567), and falls back to the legacy `initialize` handshake for older servers. The
        session is cleaned up when the context exits.


        Yields:
            tuple: The connected client and the server name reported by it.
        """
        headers = await self._resolve_headers()
        async with (
            httpx2.AsyncClient(headers=headers, verify=self.verify) as custom_httpx_client,
            MCPClient(
                streamable_http_client(url=self.base_url, http_client=custom_httpx_client),
                mode="auto",
            ) as session,
        ):
            demisto.debug(f"Connected to MCP server using protocol version {session.protocol_version}")
            server_info = session.server_info
            yield session, server_info.name if server_info else ""

    async def test_connection(self, auth_test: bool = False):
        async with self._get_session():
            if auth_test:
                return CommandResults(readable_output="✅ Authentication successful.")
            else:
                return "ok"

    async def list_tools(self, default_server_name: str = ""):
        async with self._get_session() as (session, server_name):
            tools = await session.list_tools()

        server_name = default_server_name or server_name
        tool_names = [tool.name for tool in tools.tools]
        readable_output = f"{server_name} has {len(tool_names)} available tools:\n{tool_names}"
        demisto.debug(f"Available tools: {tool_names}")

        # by_alias keeps the camelCase wire names (inputSchema, not input_schema).
        tools_dump = tools.model_dump(mode="json", by_alias=True)
        outputs = {"server_name": server_name, "Tools": normalize_tool_schemas(tools_dump.get("tools", []))}
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="ListTools",
            outputs=outputs,
        )

    async def call_tool(self, tool_name: str, arguments: str):
        try:
            parsed_arguments = json.loads(arguments or "{}")
        except json.JSONDecodeError:
            raise DemistoException(f"Invalid JSON provided for arguments: {arguments}")

        async with self._get_session() as (session, server_name):
            result = await session.call_tool(tool_name, parsed_arguments)

        # by_alias keeps the camelCase wire names (isError, not is_error).
        result_dump = result.model_dump(mode="json", by_alias=True)
        result_content = result_dump.get("content", [])
        is_error = result.is_error
        readable_output = tableToMarkdown(
            f"Tool Execution on {server_name}: '{tool_name}'{' failed' if is_error else ''}", result_content
        )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="CallTool.Tool",
            outputs=result_content,
            entry_type=EntryType.NOTE if not is_error else EntryType.ERROR,
        )


async def generate_login_url(
    oauth_handler: OAuthHandler,
    auth_type: str = "",
    authorization_endpoint: str = "",
    redirect_uri: str = "",
    troubleshooting_redirect: bool = False,
) -> CommandResults:
    """
    Generates the login URL for the OAuth Authorization Code flow.
    This function handles both static and dynamic registration flows.
    """
    if auth_type not in (AuthMethods.AUTHORIZATION_CODE, AuthMethods.DYNAMIC_CLIENT_REGISTRATION):
        raise ValueError(
            f"To generate a login URL, 'auth_type' must be a valid OAuth flow type. Invalid type received: {auth_type}"
        )

    auth_url = ""
    context_data: dict[str, Any] = {}
    if auth_type == AuthMethods.AUTHORIZATION_CODE:
        auth_url, context_data = oauth_handler.generate_authorization_code_login_url(authorization_endpoint)

    if auth_type == AuthMethods.DYNAMIC_CLIENT_REGISTRATION:
        auth_url, context_data = await oauth_handler.generate_dynamic_registration_login_url()

    update_integration_context_oauth_flow(context_data, override=True)

    # Only promise the `iss` check when the authorization server advertised RFC 9207 support.
    # Servers that do not send `iss` (Atlassian, for example) would otherwise be described as
    # offering a protection the response cannot carry.
    oauth_metadata = build_oauth_metadata(context_data.get("oauth_metadata", {}))
    iss_supported = bool(oauth_metadata and oauth_metadata.authorization_response_iss_parameter_supported)

    redirect_structure = (
        "REDIRECT_URI?code=AUTH_CODE&state=STATE&iss=ISSUER" if iss_supported else ("REDIRECT_URI?code=AUTH_CODE&state=STATE")
    )
    verified_params = (
        "`state` and `iss` parameters, which protect against CSRF and authorization-server mix-up attacks"
        if (iss_supported)
        else "`state` parameter, which protects against CSRF attacks"
    )
    verification_noun = "these verifications are" if iss_supported else "this verification is"

    result_msg = (
        "### Authorization instructions\n"
        f"1. Click on the [login URL]({auth_url}) to sign in and grant Cortex permissions for your MCP server.\n"
        "  You will be automatically redirected to a link with the following structure:\n"
        f"  ```{redirect_structure}```\n"
        "2. Copy the **entire URL** from your browser's address bar and paste it "
        "in the instance configuration under the **Redirect URL or Authorization Code** parameter.\n"
        f"  Pasting the full URL lets Cortex verify the {verified_params}.\n"
        f"  Pasting only the `AUTH_CODE` still works, but {verification_noun} skipped, and "
        "support for it is deprecated and will be removed in a future version.\n"
        "3. Save the instance configuration.\n"
        "  **IMPORTANT NOTE**: Authentication code is time-sensitive and expires quickly.\n"
        "  Please copy the redirect URL to the instance configuration "
        "within a short time frame after generating the login URL.\n\n"
        f"4. To check connectivity, run the **!{oauth_handler.command_prefix}-auth-test** command."
    )
    if troubleshooting_redirect:
        result_msg += (
            "\n\n**Troubleshooting Redirect Errors**:\n"
            f"If you encounter a `Redirect URI` mismatch error, please ensure that `{redirect_uri}` "
            "is added to your application's allowed redirect list.\nAlternatively, you can update the **Redirect URI** "
            "parameter found in the Advanced section of your instance settings."
        )
    return CommandResults(readable_output=result_msg)
