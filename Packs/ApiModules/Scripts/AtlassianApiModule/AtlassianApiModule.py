"""Atlassian API Module - Shared OAuth 2.0 functionality for Atlassian products (Jira, Confluence)."""

import base64
import hashlib
import os
import re
import time
from abc import ABC, abstractmethod
import requests
from CommonServerPython import *  # noqa: F401

ATLASSIAN_AUTH_URL = "https://auth.atlassian.com"


class AtlassianOAuthClient(ABC):
    """
    Abstract base class for Atlassian OAuth 2.0 authentication.

    This class provides common OAuth 2.0 functionality for Atlassian Cloud products.
    Child classes should implement the abstract methods for their specific use cases.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        callback_url: str,
        cloud_id: str = "",
        verify: bool = True,
        proxy: bool = False,
    ):
        """
        Initialize the Atlassian OAuth client.

        Args:
            client_id: OAuth 2.0 Client ID
            client_secret: OAuth 2.0 Client Secret
            callback_url: OAuth callback/redirect URL
            cloud_id: Jira Cloud ID (required for Cloud instances)
            verify: Whether to verify SSL certificates
            proxy: Whether to use proxy settings
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.callback_url = callback_url
        self.cloud_id = cloud_id
        self.verify = verify
        self.proxy = proxy

    @abstractmethod
    def get_oauth_scopes(self) -> list[str]:
        """
        Return the list of OAuth scopes required for this integration.

        Returns:
            List of OAuth scope strings
        """

    def get_access_token(self) -> str:
        """
        Get the access token from integration context or refresh if expired.

        Returns:
            Valid access token

        Raises:
            DemistoException: If no access token or refresh token is available
        """
        integration_context = get_integration_context()
        token = integration_context.get("token", "")

        if not token:
            raise DemistoException(
                "No access token configured. Please complete the authorization process using "
                "the oauth-start and oauth-complete commands"
            )

        # Check if token is expired (with 10 second buffer)
        valid_until = integration_context.get("valid_until", 0)
        current_time = time.time()

        if current_time >= valid_until - 10:
            refresh_token = integration_context.get("refresh_token", "")
            if not refresh_token:
                raise DemistoException("No refresh token configured. Please complete the authorization process")
            # Refresh the access token
            self.oauth2_retrieve_access_token(refresh_token=refresh_token)
            integration_context = get_integration_context()
            token = integration_context.get("token", "")

        return token

    def oauth2_retrieve_access_token(self, code: str = "", refresh_token: str = "") -> None:
        """
        Exchange authorization code or refresh token for access token.

        Args:
            code: Authorization code from OAuth callback
            refresh_token: Refresh token for renewing access token

        Raises:
            DemistoException: If both or neither code and refresh_token are provided
        """
        if code and refresh_token:
            raise DemistoException("Both authorization code and refresh token were provided. Please provide only one")
        if not (code or refresh_token):
            raise DemistoException("No authorization code or refresh token provided")

        grant_type = "authorization_code" if code else "refresh_token"
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            redirect_uri=self.callback_url if code else "",
            refresh_token=refresh_token,
            grant_type=grant_type,
        )

        token_url = urljoin(ATLASSIAN_AUTH_URL, "oauth/token")
        demisto.debug(f"Requesting OAuth token from {token_url} with grant_type={grant_type}")
        try:
            response = requests.post(
                token_url,
                data=data,
                verify=self.verify,
                proxies=handle_proxy() if self.proxy else None,
                timeout=60,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            demisto.debug(f"OAuth token request failed with status {e.response.status_code}: {e.response.text}")
            raise DemistoException(f"Failed to retrieve OAuth token (HTTP {e.response.status_code}): {e.response.text}") from e
        except requests.exceptions.RequestException as e:
            demisto.debug(f"OAuth token request failed: {e}")
            raise DemistoException(f"Failed to connect to OAuth token endpoint: {e}") from e

        res_access_token = response.json()
        demisto.debug("Successfully retrieved OAuth token")

        integration_context = get_integration_context()
        new_authorization_context = {
            "token": res_access_token.get("access_token", ""),
            "scopes": res_access_token.get("scope", ""),
            "valid_until": time.time() + res_access_token.get("expires_in", 0),
            "refresh_token": res_access_token.get("refresh_token", ""),
        }
        integration_context |= new_authorization_context
        set_integration_context(integration_context)

    def oauth_start(self) -> str:
        """
        Start OAuth flow and return authorization URL.

        Constructs the Atlassian OAuth 2.0 (3LO) authorization URL with all required
        parameters including the 'state' parameter (required by Atlassian).

        Returns:
            Authorization URL for user to visit

        Raises:
            DemistoException: If no URL is returned
        """
        scopes = self.get_oauth_scopes()

        # Generate a random state parameter for CSRF protection (required by Atlassian)
        state = base64.urlsafe_b64encode(os.urandom(24)).decode("utf-8")

        # Store state in integration context for validation on callback
        integration_context = get_integration_context()
        integration_context["oauth_state"] = state
        set_integration_context(integration_context)

        params = assign_params(
            audience="api.atlassian.com",
            client_id=self.client_id,
            scope=" ".join(scopes),
            redirect_uri=self.callback_url,
            state=state,
            response_type="code",
            prompt="consent",
        )

        # Build the authorization URL directly instead of making a request
        # Atlassian OAuth 2.0 (3LO) requires the user to visit the URL directly
        from urllib.parse import urlencode

        auth_url = f"{ATLASSIAN_AUTH_URL}/authorize?{urlencode(params)}"

        return auth_url

    def oauth_complete(self, code: str) -> None:
        """
        Complete OAuth flow by exchanging authorization code for tokens.

        Args:
            code: Authorization code from OAuth callback
        """
        self.oauth2_retrieve_access_token(code=code)

    def test_connection(self) -> None:
        """
        Test the OAuth connection by attempting to get an access token.

        Raises:
            DemistoException: If authentication fails
        """
        self.get_access_token()


class JiraCloudOAuthClient(AtlassianOAuthClient):
    """OAuth client specifically for Jira Cloud instances."""

    def get_oauth_scopes(self) -> list[str]:
        """
        Return the OAuth scopes required for Jira Cloud.

        The audit log API requires both the classic 'manage:jira-configuration' scope
        and the granular 'read:audit-log:jira' scope. The classic scope is needed because
        the audit endpoint is an admin-level API. Both must also be configured in the
        Atlassian Developer Console for the OAuth app.

        Returns:
            List of required OAuth scopes
        """
        return [
            "read:audit-log:jira",  # Granular scope for audit log access
            "manage:jira-configuration",  # Classic admin scope required by audit API
            "read:jira-work",  # Required for API v3 access
            "read:jira-user",  # User info access
            "offline_access",  # For refresh token
        ]


class ConfluenceCloudOAuthClient(AtlassianOAuthClient):
    """OAuth client specifically for Confluence Cloud instances."""

    def get_oauth_scopes(self) -> list[str]:
        """
        Return the OAuth scopes required for Confluence Cloud.

        This is the full granular scope set required to authorize both the v2
        page/blogpost/space/comment commands and the retained v1 search/user/group/audit
        commands with a single access token. Granular scopes must not be mixed with
        classic scopes in the same authorize request.

        Returns:
            List of required OAuth scopes
        """
        return [
            "read:content:confluence",
            "write:content:confluence",
            "read:content-details:confluence",
            "read:space-details:confluence",
            "delete:content:confluence",
            "read:audit-log:confluence",
            "read:page:confluence",
            "write:page:confluence",
            "delete:page:confluence",
            "read:blogpost:confluence",
            "write:blogpost:confluence",
            "delete:blogpost:confluence",
            "read:custom-content:confluence",
            "write:custom-content:confluence",
            "delete:custom-content:confluence",
            "read:comment:confluence",
            "write:comment:confluence",
            "delete:comment:confluence",
            "read:template:confluence",
            "write:template:confluence",
            "read:label:confluence",
            "write:label:confluence",
            "read:watcher:confluence",
            "read:space:confluence",
            "write:space:confluence",
            "delete:space:confluence",
            "read:group:confluence",
            "offline_access",  # For refresh token
        ]


class JiraOnPremOAuthClient(AtlassianOAuthClient):
    """OAuth client specifically for Jira On-Prem/Data Center instances."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        callback_url: str,
        server_url: str,
        verify: bool = True,
        proxy: bool = False,
    ):
        """
        Initialize the Jira On-Prem OAuth client.

        Args:
            client_id: OAuth 2.0 Client ID
            client_secret: OAuth 2.0 Client Secret
            callback_url: OAuth callback/redirect URL
            server_url: Jira server URL (e.g., https://jira.company.com)
            verify: Whether to verify SSL certificates
            proxy: Whether to use proxy settings
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            callback_url=callback_url,
            cloud_id="",  # Not used for on-prem
            verify=verify,
            proxy=proxy,
        )
        self.server_url = server_url.rstrip("/")

    def get_oauth_scopes(self) -> list[str]:
        """
        Return the OAuth scopes required for Jira On-Prem.

        Returns:
            List of required OAuth scopes (On-Prem uses single scope string)
        """
        return ["ADMIN"]

    def oauth_start(self) -> str:
        """
        Start OAuth flow for On-Prem and return authorization URL.
        Uses PKCE (Proof Key for Code Exchange) for enhanced security.

        Returns:
            Authorization URL for user to visit

        Raises:
            DemistoException: If no URL is returned
        """
        integration_context = get_integration_context()
        try:
            # Generate PKCE code verifier and challenge
            code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
            code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
            code_challenge_bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()
            code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).decode("utf-8")
            code_challenge = code_challenge.replace("=", "")

            # Store code_verifier in integration context for later use
            integration_context["code_verifier"] = code_verifier
            set_integration_context(integration_context)

            params = assign_params(
                client_id=self.client_id,
                scope=" ".join(self.get_oauth_scopes()),
                redirect_uri=self.callback_url,
                code_challenge=code_challenge,
                code_challenge_method="S256",
                response_type="code",
            )

            authorize_url = f"{self.server_url}/rest/oauth2/latest/authorize"
            demisto.debug(f"Requesting On-Prem OAuth authorization from {authorize_url}")
            response = requests.get(
                authorize_url,
                params=params,
                verify=self.verify,
                proxies=handle_proxy() if self.proxy else None,
                allow_redirects=False,
                timeout=60,
            )
            demisto.debug(f"On-Prem OAuth authorization response status: {response.status_code}")

            if response.url:
                return response.url
            raise DemistoException("No authorization URL was returned")
        except Exception:
            # Clean up code_verifier from integration context on failure
            integration_context.pop("code_verifier", None)
            set_integration_context(integration_context)
            raise

    def oauth2_retrieve_access_token(self, code: str = "", refresh_token: str = "") -> None:
        """
        Exchange authorization code or refresh token for access token (On-Prem version).

        Args:
            code: Authorization code from OAuth callback
            refresh_token: Refresh token for renewing access token

        Raises:
            DemistoException: If both or neither code and refresh_token are provided
        """
        if code and refresh_token:
            raise DemistoException("Both authorization code and refresh token were provided. Please provide only one")
        if not (code or refresh_token):
            raise DemistoException("No authorization code or refresh token provided")

        integration_context = get_integration_context()
        # Pop code_verifier as it's only needed during initial authorization
        code_verifier = integration_context.pop("code_verifier", "")

        grant_type = "authorization_code" if code else "refresh_token"
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code_verifier=code_verifier if code else "",
            code=code,
            redirect_uri=self.callback_url if code else "",
            refresh_token=refresh_token,
            grant_type=grant_type,
        )

        token_url = f"{self.server_url}/rest/oauth2/latest/token"
        demisto.debug(f"Requesting On-Prem OAuth token from {token_url} with grant_type={grant_type}")
        try:
            response = requests.post(
                token_url,
                data=data,
                verify=self.verify,
                proxies=handle_proxy() if self.proxy else None,
                timeout=60,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            demisto.debug(f"On-Prem OAuth token request failed with status {e.response.status_code}: {e.response.text}")
            raise DemistoException(
                f"Failed to retrieve On-Prem OAuth token (HTTP {e.response.status_code}): {e.response.text}"
            ) from e
        except requests.exceptions.RequestException as e:
            demisto.debug(f"On-Prem OAuth token request failed: {e}")
            raise DemistoException(f"Failed to connect to On-Prem OAuth token endpoint: {e}") from e

        res_access_token = response.json()
        demisto.debug("Successfully retrieved On-Prem OAuth token")

        new_authorization_context = {
            "token": res_access_token.get("access_token", ""),
            "scopes": res_access_token.get("scope", ""),
            "valid_until": time.time() + res_access_token.get("expires_in", 0),
            "refresh_token": res_access_token.get("refresh_token", ""),
        }
        integration_context |= new_authorization_context
        set_integration_context(integration_context)


def create_atlassian_oauth_client(
    client_id: str,
    client_secret: str,
    callback_url: str,
    cloud_id: str = "",
    server_url: str = "",
    verify: bool = True,
    proxy: bool = False,
    product: str = "jira",
):
    """
    Factory function to create an Atlassian OAuth client.

    Automatically determines whether to create a Cloud or On-Prem client
    based on the presence of cloud_id.

    Args:
        client_id: OAuth 2.0 Client ID
        client_secret: OAuth 2.0 Client Secret
        callback_url: OAuth callback/redirect URL
        cloud_id: Cloud ID (if provided, creates Cloud client)
        server_url: Server URL (for On-Prem instances)
        verify: Whether to verify SSL certificates
        proxy: Whether to use proxy settings
        product: Product type ('jira' or 'confluence')

    Returns:
        Configured Cloud or On-Prem OAuth client instance
    """
    if cloud_id:
        # Cloud instance
        if product.lower() == "confluence":
            return ConfluenceCloudOAuthClient(
                client_id=client_id,
                client_secret=client_secret,
                callback_url=callback_url,
                cloud_id=cloud_id,
                verify=verify,
                proxy=proxy,
            )
        else:
            return JiraCloudOAuthClient(
                client_id=client_id,
                client_secret=client_secret,
                callback_url=callback_url,
                cloud_id=cloud_id,
                verify=verify,
                proxy=proxy,
            )
    else:
        # On-Prem instance (currently only Jira is supported)
        return JiraOnPremOAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            callback_url=callback_url,
            server_url=server_url,
            verify=verify,
            proxy=proxy,
        )


# Backward-compatible alias for integrations that import by the old name
create_jira_oauth_client = create_atlassian_oauth_client


""" CONNECTUS (UCP) HELPERS """
# Shared by every Atlassian integration that runs under the Atlassian standard
# connector. On the UCP path the connector delivers the credential through a typed
# connection profile (oauth2_*, api_key or plain) instead of demisto.params().
# BaseClient._http_request applies it on every request; integrations that do not
# send their requests through BaseClient read it with get_atlassian_ucp_auth().

ATLASSIAN_UCP_AUTH_OAUTH2 = "oauth2"
ATLASSIAN_UCP_AUTH_API_KEY = "api_key"
ATLASSIAN_UCP_AUTH_PLAIN = "plain"


def get_atlassian_ucp_auth_type() -> str:
    """
    Return the credential family of the connection profile selected for this command.

    Returns:
        "oauth2", "api_key" or "plain" when UCP auth is active, "" otherwise.
    """
    if not should_use_ucp_auth():
        return ""
    profile_type = ""
    try:
        method_unique_id = get_ucp_method_unique_id()
        for profile in demisto.unifiedConnectorMetadata().get("connectionProfiles") or []:
            if profile.get("method_unique_id") == method_unique_id:
                profile_type = profile.get("type") or ""
                break
    except Exception as e:  # pragma: no cover - defensive, metadata is platform-provided
        demisto.debug(f"[UCP][AtlassianApiModule.py] could not resolve the profile type ({e}).")
    if profile_type.startswith("oauth2"):
        return ATLASSIAN_UCP_AUTH_OAUTH2
    if profile_type in (ATLASSIAN_UCP_AUTH_API_KEY, ATLASSIAN_UCP_AUTH_PLAIN):
        return profile_type
    # Fall back to the envelope type for profiles the metadata did not describe.
    credentials = get_ucp_credentials()
    envelope_type = str(credentials.get("type") or "")
    return ATLASSIAN_UCP_AUTH_OAUTH2 if envelope_type.startswith("oauth2") else envelope_type


def get_atlassian_ucp_auth() -> dict[str, Any]:
    """
    Read the UCP credential of the selected connection profile in a flat shape.

    For integrations whose HTTP layer does not go through BaseClient._http_request
    (so BaseClient cannot inject the credential for them).

    Returns:
        {"type": "oauth2", "access_token": ..., "token_type": ...}
        {"type": "api_key", "key": ...}
        {"type": "plain", "username": ..., "password": ...}

    Raises:
        UcpException: If the profile type is not one of the three families, or the
            required secret is empty.
    """
    credentials = get_ucp_credentials()
    envelope_type = str(credentials.get("type") or "")
    if envelope_type.startswith("oauth2"):
        data = credentials.get("oauth2", credentials)
        access_token = data.get("access_token", "")
        if not access_token:
            demisto.error("[UCP][AtlassianApiModule.py] access_token is empty in the UCP OAuth2 credentials.")
            raise UcpException
        return {
            "type": ATLASSIAN_UCP_AUTH_OAUTH2,
            "access_token": access_token,
            "token_type": data.get("token_type") or "Bearer",
        }
    if envelope_type == ATLASSIAN_UCP_AUTH_API_KEY:
        key = credentials.get("api_key", credentials).get("key", "")
        if not key:
            demisto.error("[UCP][AtlassianApiModule.py] the API key is empty in the UCP credentials.")
            raise UcpException
        return {"type": ATLASSIAN_UCP_AUTH_API_KEY, "key": key}
    if envelope_type == ATLASSIAN_UCP_AUTH_PLAIN:
        data = credentials.get("plain", credentials)
        username = data.get("username", "")
        if not username:
            demisto.error("[UCP][AtlassianApiModule.py] the username is empty in the UCP plain credentials.")
            raise UcpException
        return {"type": ATLASSIAN_UCP_AUTH_PLAIN, "username": username, "password": data.get("password", "")}
    demisto.error(f'[UCP][AtlassianApiModule.py] unsupported credential type "{envelope_type}".')
    raise UcpException


def build_atlassian_ucp_auth_headers() -> tuple[dict[str, str], tuple[str, str] | None]:
    """
    Turn the UCP credential into request auth for a client that is not a BaseClient.

    Returns:
        (headers, basic_auth): an Authorization header for oauth2 / api_key profiles
        (both are bearer tokens for Atlassian), or a (username, password) tuple for
        a plain profile.
    """
    auth = get_atlassian_ucp_auth()
    if auth["type"] == ATLASSIAN_UCP_AUTH_OAUTH2:
        return {"Authorization": f"{auth['token_type']} {auth['access_token']}"}, None
    if auth["type"] == ATLASSIAN_UCP_AUTH_API_KEY:
        return {"Authorization": f"Bearer {auth['key']}"}, None
    return {}, (auth["username"], auth["password"])


def resolve_atlassian_cloud_base_url(product: str, cloud_id: str, site_url: str = "") -> str:
    """
    Return the REST base URL for an Atlassian Cloud product under the given auth.

    OAuth 2.0 (3LO) tokens are only accepted on the API gateway
    (https://api.atlassian.com/ex/<product>/<cloud_id>); email + API token (Basic)
    works on the site URL as well, so the site is used when it is configured.

    Args:
        product: "jira" or "confluence".
        cloud_id: The Atlassian site Cloud ID.
        site_url: The site URL (https://<site>.atlassian.net), used for Basic auth.

    Raises:
        DemistoException: If the Cloud ID is missing for an OAuth 2.0 profile.
    """
    if get_atlassian_ucp_auth_type() == ATLASSIAN_UCP_AUTH_OAUTH2 or not site_url:
        if not cloud_id:
            raise DemistoException("The Cloud ID is required for Atlassian Cloud OAuth 2.0. Set it on the connection page.")
        return f"https://api.atlassian.com/ex/{product}/{cloud_id}"
    return site_url.rstrip("/")
