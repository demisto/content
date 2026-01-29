"""Atlassian API Module - Shared OAuth 2.0 functionality for Atlassian products (Jira, Confluence)."""
import base64
import hashlib
import os
import re
import time
from abc import ABC, abstractmethod
from urllib.parse import urljoin

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
        Initialize the Jira OAuth client.

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
        pass

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
                raise DemistoException(
                    "No refresh token configured. Please complete the authorization process"
                )
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
            raise DemistoException(
                "Both authorization code and refresh token were provided. Please provide only one"
            )
        if not (code or refresh_token):
            raise DemistoException(
                "No authorization code or refresh token provided"
            )

        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            redirect_uri=self.callback_url if code else "",
            refresh_token=refresh_token,
            grant_type="authorization_code" if code else "refresh_token",
        )
        
        response = requests.post(
            urljoin(ATLASSIAN_AUTH_URL, "oauth/token"),
            data=data,
            verify=self.verify,
            proxies=handle_proxy() if self.proxy else None
        )
        response.raise_for_status()
        res_access_token = response.json()
        
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
        
        Returns:
            Authorization URL for user to visit
            
        Raises:
            DemistoException: If no URL is returned
        """
        scopes = self.get_oauth_scopes()
        
        params = assign_params(
            audience="api.atlassian.com",
            client_id=self.client_id,
            scope=" ".join(scopes),
            redirect_uri=self.callback_url,
            response_type="code",
            prompt="consent",
        )
        
        response = requests.get(
            urljoin(ATLASSIAN_AUTH_URL, "authorize"),
            params=params,
            verify=self.verify,
            proxies=handle_proxy() if self.proxy else None,
            allow_redirects=False
        )
        
        if response.url:
            return response.url
        raise DemistoException("No authorization URL was returned")

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
        
        Returns:
            List of required OAuth scopes
        """
        return [
            "read:audit-log:jira",
            "read:jira-user",
            "offline_access",  # For refresh token
        ]


class ConfluenceCloudOAuthClient(AtlassianOAuthClient):
    """OAuth client specifically for Confluence Cloud instances."""

    def get_oauth_scopes(self) -> list[str]:
        """
        Return the OAuth scopes required for Confluence Cloud.
        
        Returns:
            List of required OAuth scopes
        """
        return [
            "read:audit-log:confluence",
            "read:confluence-content.all",
            "read:confluence-space.summary",
            "read:confluence-user",
            "read:confluence-groups",
            "write:confluence-content",
            "write:confluence-space",
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
        # Generate PKCE code verifier and challenge
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
        code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
        code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
        code_challenge = code_challenge.replace("=", "")
        
        # Store code_verifier in integration context for later use
        integration_context = get_integration_context()
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
        
        response = requests.get(
            f"{self.server_url}/rest/oauth2/latest/authorize",
            params=params,
            verify=self.verify,
            proxies=handle_proxy() if self.proxy else None,
            allow_redirects=False
        )
        
        if response.url:
            return response.url
        raise DemistoException("No authorization URL was returned")

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
            raise DemistoException(
                "Both authorization code and refresh token were provided. Please provide only one"
            )
        if not (code or refresh_token):
            raise DemistoException(
                "No authorization code or refresh token provided"
            )

        integration_context = get_integration_context()
        # Pop code_verifier as it's only needed during initial authorization
        code_verifier = integration_context.pop("code_verifier", "")
        
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code_verifier=code_verifier if code else "",
            code=code,
            redirect_uri=self.callback_url if code else "",
            refresh_token=refresh_token,
            grant_type="authorization_code" if code else "refresh_token",
        )
        
        response = requests.post(
            f"{self.server_url}/rest/oauth2/latest/token",
            data=data,
            verify=self.verify,
            proxies=handle_proxy() if self.proxy else None
        )
        response.raise_for_status()
        res_access_token = response.json()
        
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
