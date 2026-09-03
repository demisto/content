"""Prisma AIRs shared API module.

Holds the plane-agnostic transport layer shared by every Prisma AIRs integration
(AI Red Teaming, AI Runtime Security, AI Model Security, AI Gateway):

* ``Client`` — OAuth2 (client_credentials) auth against Strata Cloud Manager plus
  ``http_request`` with the full set of plane-routing flags, and ``scanner_request``
  for the API-key-authenticated runtime scanner.
* Truly-shared constants (limits, output prefix, plane path prefixes, default base URLs).
* ``test_module`` — a plane-agnostic OAuth connectivity check.

Each integration imports this module with a wildcard import; the demisto-sdk unifier then
inlines this file into every integration at build/upload time. Domain-specific endpoint
constants and command functions live in their owning integration, not here.
"""

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from typing import Any

# CONSTANTS (shared across all Prisma AIRs integrations)
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
DEFAULT_LIMIT = 50
PA_OUTPUT_PREFIX = "PrismaAIRs."
# Plane path prefixes (appended to Server URL from config) - referenced by Client.http_request.
MGMT_API_PATH = "/aisec"
MODEL_SEC_DATA_PATH = "/aims/data"
MODEL_SEC_MGMT_PATH = "/aims/mgmt"
RED_TEAM_DATA_PATH = "/ai-red-teaming/data-plane"
RED_TEAM_MGMT_PATH = "/ai-red-teaming/mgmt-plane"
# DLP v2 API uses a completely separate base URL (NOT the SCM base URL).
DEFAULT_DLP_BASE_URL = "https://api.dlp.paloaltonetworks.com"
# Scanner API (runtime sync scan) - API-key auth, separate regional base URL.
SCANNER_SYNC_SCAN_PATH = "/v1/scan/sync/request"
DEFAULT_SCANNER_BASE_URL = "https://service.api.aisecurity.paloaltonetworks.com"

# OAuth2 token endpoint (SCM).
TOKEN_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"


class Client(BaseClient):
    """Client class to interact with Prisma AIRs API.

    This Client implements the shared transport for the Prisma AIRs platform via Strata
    Cloud Manager and does not contain any XSOAR command logic. Handles OAuth2 token
    retrieval and plane routing for every Prisma AIRs integration.

    All credential/URL fields are optional so an integration that only configures its own
    plane (scoped credentials) constructs cleanly; required fields are validated in each
    integration's ``test-module``, not here.

    Args:
       base_url: Strata Cloud Manager server URL.
       client_id: OAuth2 client ID.
       client_secret: OAuth2 client secret.
       tsg_id: The default Prisma SASE Tenant Services Group ID.
       runtime_api_key: API key for the runtime scanner (Runtime integration only).
       scanner_base_url: Override for the runtime scanner base URL.
       dlp_base_url: Override for the DLP v2 API base URL.
       verify: Specifies whether to verify the SSL certificate or not.
       proxy: Specifies if to use XSOAR proxy settings.
       headers: Base HTTP headers.
    """

    def __init__(
        self,
        base_url: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        tsg_id: str | None = None,
        runtime_api_key: str | None = None,
        scanner_base_url: str | None = None,
        dlp_base_url: str | None = None,
        verify: bool = True,
        proxy: bool = False,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, **kwargs)

        self.client_id = client_id
        self.client_secret = client_secret
        self.tsg_id = tsg_id
        self.runtime_api_key = runtime_api_key
        # Use configured URLs or fall back to defaults
        self.scanner_base_url = scanner_base_url or DEFAULT_SCANNER_BASE_URL
        self.dlp_base_url = dlp_base_url or DEFAULT_DLP_BASE_URL
        self._access_token: str | None = None

    def get_access_token(self) -> str:
        """Retrieve OAuth2 access token from SCM token endpoint.

        Returns:
            str: Access token for API authentication.
        """
        if self._access_token:
            return self._access_token

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": f"profile tsg_id:{self.tsg_id}" if self.tsg_id else "profile",
        }

        response = self._http_request(method="POST", full_url=TOKEN_URL, headers=headers, data=data, resp_type="json")

        self._access_token = response.get("access_token")
        if not self._access_token:
            raise DemistoException("Failed to retrieve access token from SCM")

        return self._access_token

    def http_request(
        self,
        method: str,
        url_suffix: str = "",
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        tsg_id: str | None = None,
        use_mgmt_base: bool = False,
        use_model_sec_data: bool = False,
        use_model_sec_mgmt: bool = False,
        use_redteam_data: bool = False,
        use_redteam_mgmt: bool = False,
        use_dlp_base: bool = False,
        resp_type: str = "json",
        return_empty_response: bool = False,
        headers: dict[str, str] | None = None,
        files: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute HTTP request with OAuth2 authentication for Management API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            url_suffix: URL suffix to append to base URL.
            params: URL parameters.
            json_data: JSON data for request body.
            tsg_id: Override TSG ID for this request.
            use_mgmt_base: If True, use MGMT_API_PATH prefix (e.g., /aisec/v1/mgmt/...).
            use_model_sec_data: If True, use MODEL_SEC_DATA_PATH prefix (e.g., /aims/data/...).
            use_model_sec_mgmt: If True, use MODEL_SEC_MGMT_PATH prefix (e.g., /aims/mgmt/...).
            use_redteam_data: If True, use RED_TEAM_DATA_PATH prefix (e.g., /ai-red-teaming/data-plane/...).
            use_redteam_mgmt: If True, use RED_TEAM_MGMT_PATH prefix (e.g., /ai-red-teaming/mgmt-plane/...).
            use_dlp_base: If True, use DLP_BASE_URL (https://api.dlp.paloaltonetworks.com) + url_suffix directly.
            resp_type: Response type - "json" (default), "text", "content", "xml", or "response".
            return_empty_response: If True, return empty response object for 204 No Content responses (DELETE operations).

        Returns:
            dict: API response.
        """
        token = self.get_access_token()
        # 'service-name: api' is required by some tenants' downstream services (notably the DLP API),
        # which otherwise return a generic HTTP 400. Sent on every management/DLP request to match the SDK.
        request_headers: dict[str, str] = {"Authorization": f"Bearer {token}", "service-name": "api"}
        # For multipart file uploads, let the HTTP layer set the Content-Type (with boundary).
        if files is None:
            request_headers["Content-Type"] = "application/json"
        # Allow callers to override/add headers (e.g., application/merge-patch+json for PATCH).
        if headers:
            request_headers.update(headers)

        # Determine which API path prefix to use
        # CRITICAL: DLP v2 API uses a completely different base URL
        if use_dlp_base:
            full_url = f"{self.dlp_base_url}{url_suffix}"
        elif use_model_sec_data:
            full_url = f"{self._base_url}{MODEL_SEC_DATA_PATH}{url_suffix}"
        elif use_model_sec_mgmt:
            full_url = f"{self._base_url}{MODEL_SEC_MGMT_PATH}{url_suffix}"
        elif use_redteam_data:
            full_url = f"{self._base_url}{RED_TEAM_DATA_PATH}{url_suffix}"
        elif use_redteam_mgmt:
            full_url = f"{self._base_url}{RED_TEAM_MGMT_PATH}{url_suffix}"
        elif use_mgmt_base:
            full_url = f"{self._base_url}{MGMT_API_PATH}{url_suffix}"
        else:
            # Use default base URL without additional prefix
            return self._http_request(
                method=method,
                url_suffix=url_suffix,
                params=params,
                json_data=json_data,
                files=files,
                headers=request_headers,
                resp_type=resp_type,
                return_empty_response=return_empty_response,
            )

        return self._http_request(
            method=method,
            full_url=full_url,
            params=params,
            json_data=json_data,
            files=files,
            headers=request_headers,
            resp_type=resp_type,
            return_empty_response=return_empty_response,
        )

    def scanner_request(
        self,
        json_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute scanner API request with API key authentication.

        Args:
            json_data: JSON data for scanner request body.

        Returns:
            dict: Scanner API response.
        """
        if not self.runtime_api_key:
            raise DemistoException(
                "Runtime API Key is required for scanner operations. "
                "Please configure the Runtime API Key in the integration settings."
            )

        headers = {"x-pan-token": self.runtime_api_key, "Content-Type": "application/json"}

        # Use regional scanner endpoint + sync scan path
        # Full URL: https://service{-region}.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request
        return self._http_request(
            method="POST",
            full_url=f"{self.scanner_base_url}{SCANNER_SYNC_SCAN_PATH}",
            json_data=json_data,
            headers=headers,
            resp_type="json",
        )


def test_module(client: Client) -> str:
    """Test connectivity to Prisma AIRs API.

    Plane-agnostic OAuth check shared by every integration. Integrations that need a
    stronger, plane-specific probe may wrap this with an additional read.

    Args:
        client: Prisma AIRs API client.

    Returns:
        str: 'ok' if test passed, error message otherwise.
    """
    try:
        # Test authentication by attempting to get access token
        client.get_access_token()
        return "ok"
    except Exception as e:
        return f"Test failed: {str(e)}"
