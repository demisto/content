"""Unit tests for PrismaAirsApiModule (shared Prisma AIRs transport layer)."""

from typing import Any
from unittest.mock import Mock, patch

import pytest
from PrismaAirsApiModule import (
    DEFAULT_DLP_BASE_URL,
    DEFAULT_SCANNER_BASE_URL,
    MGMT_API_PATH,
    MODEL_SEC_DATA_PATH,
    MODEL_SEC_MGMT_PATH,
    RED_TEAM_DATA_PATH,
    RED_TEAM_MGMT_PATH,
    SCANNER_SYNC_SCAN_PATH,
    TOKEN_URL,
    Client,
)
from PrismaAirsApiModule import test_module as run_test_module

BASE_URL = "https://api.sase.paloaltonetworks.com"


@pytest.fixture
def mock_client() -> Client:
    """Create a fully-configured mock Prisma AIRs client."""
    return Client(
        base_url=BASE_URL,
        client_id="test_client_id",
        client_secret="test_client_secret",
        tsg_id="1234567890",
        runtime_api_key="test_runtime_api_key_12345",
        scanner_base_url=DEFAULT_SCANNER_BASE_URL,
        dlp_base_url=DEFAULT_DLP_BASE_URL,
        verify=False,
        proxy=False,
        headers={},
    )


class TestClientInit:
    """Client construction / scoped-credential hardening."""

    def test_full_initialization(self, mock_client: Client) -> None:
        """All provided fields are stored verbatim."""
        assert mock_client.client_id == "test_client_id"
        assert mock_client.client_secret == "test_client_secret"
        assert mock_client.tsg_id == "1234567890"
        assert mock_client.runtime_api_key == "test_runtime_api_key_12345"
        assert mock_client.scanner_base_url == DEFAULT_SCANNER_BASE_URL
        assert mock_client.dlp_base_url == DEFAULT_DLP_BASE_URL
        assert mock_client._access_token is None

    def test_scoped_credentials_construct_cleanly(self) -> None:
        """A scoped integration configuring only base_url must construct without error.

        All credential/URL fields are optional so per-plane integrations (scoped creds)
        don't have to pass fields they never use.
        """
        client = Client(base_url=BASE_URL)

        assert client.client_id is None
        assert client.client_secret is None
        assert client.tsg_id is None
        assert client.runtime_api_key is None
        # URL fields still fall back to global defaults.
        assert client.scanner_base_url == DEFAULT_SCANNER_BASE_URL
        assert client.dlp_base_url == DEFAULT_DLP_BASE_URL

    def test_base_url_defaults(self) -> None:
        """None scanner/DLP URLs fall back to documented global defaults."""
        client = Client(base_url=BASE_URL, scanner_base_url=None, dlp_base_url=None)

        assert client.scanner_base_url == DEFAULT_SCANNER_BASE_URL
        assert client.dlp_base_url == DEFAULT_DLP_BASE_URL

    def test_base_url_override(self) -> None:
        """Explicit scanner/DLP URLs are stored as provided (regional endpoints)."""
        client = Client(
            base_url=BASE_URL,
            scanner_base_url="https://service-de.api.aisecurity.paloaltonetworks.com",
            dlp_base_url="https://api-de.dlp.paloaltonetworks.com",
        )

        assert client.scanner_base_url == "https://service-de.api.aisecurity.paloaltonetworks.com"
        assert client.dlp_base_url == "https://api-de.dlp.paloaltonetworks.com"


class TestGetAccessToken:
    """OAuth2 client_credentials token retrieval."""

    @patch.object(Client, "_http_request")
    def test_success(self, mock_http_request: Mock, mock_client: Client) -> None:
        """Token is fetched from the SCM endpoint and cached on the client."""
        mock_http_request.return_value = {"access_token": "tok_12345", "token_type": "Bearer", "expires_in": 3600}

        token = mock_client.get_access_token()

        assert token == "tok_12345"
        assert mock_client._access_token == "tok_12345"
        mock_http_request.assert_called_once()
        # Verify it POSTs to the SCM token URL with a tsg-scoped scope.
        _, kwargs = mock_http_request.call_args
        assert kwargs["full_url"] == TOKEN_URL
        assert kwargs["method"] == "POST"
        assert kwargs["data"]["scope"] == "profile tsg_id:1234567890"

    @patch.object(Client, "_http_request")
    def test_scope_without_tsg(self, mock_http_request: Mock) -> None:
        """Without a tsg_id the scope degrades to bare 'profile'."""
        mock_http_request.return_value = {"access_token": "tok"}
        client = Client(base_url=BASE_URL, client_id="cid", client_secret="secret")

        client.get_access_token()

        _, kwargs = mock_http_request.call_args
        assert kwargs["data"]["scope"] == "profile"

    @patch.object(Client, "_http_request")
    def test_cached(self, mock_http_request: Mock, mock_client: Client) -> None:
        """A cached token short-circuits the HTTP call."""
        mock_client._access_token = "cached_token"

        token = mock_client.get_access_token()

        assert token == "cached_token"
        mock_http_request.assert_not_called()

    @patch.object(Client, "_http_request")
    def test_missing_token_raises(self, mock_http_request: Mock, mock_client: Client) -> None:
        """An SCM response without access_token raises."""
        mock_http_request.return_value = {"token_type": "Bearer"}

        with pytest.raises(Exception, match="Failed to retrieve access token"):
            mock_client.get_access_token()


class TestHttpRequestRouting:
    """Plane-routing flags select the correct base URL / path prefix."""

    @patch.object(Client, "get_access_token", return_value="tok")
    @patch.object(Client, "_http_request")
    def test_default_base_no_prefix(self, mock_http: Mock, _tok: Mock, mock_client: Client) -> None:
        """With no plane flag, the request uses url_suffix against the configured base URL."""
        mock_client.http_request("GET", "/v1/thing")

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/thing"
        assert "full_url" not in kwargs
        assert kwargs["headers"]["Authorization"] == "Bearer tok"
        assert kwargs["headers"]["service-name"] == "api"

    @pytest.mark.parametrize(
        "flag,prefix",
        [
            ("use_mgmt_base", MGMT_API_PATH),
            ("use_model_sec_data", MODEL_SEC_DATA_PATH),
            ("use_model_sec_mgmt", MODEL_SEC_MGMT_PATH),
            ("use_redteam_data", RED_TEAM_DATA_PATH),
            ("use_redteam_mgmt", RED_TEAM_MGMT_PATH),
        ],
    )
    @patch.object(Client, "get_access_token", return_value="tok")
    @patch.object(Client, "_http_request")
    def test_plane_prefixes(self, mock_http: Mock, _tok: Mock, mock_client: Client, flag: str, prefix: str) -> None:
        """Each plane flag prepends its path prefix to the SCM base URL."""
        flags: dict[str, Any] = {flag: True}
        mock_client.http_request("GET", "/v1/thing", **flags)

        _, kwargs = mock_http.call_args
        assert kwargs["full_url"] == f"{BASE_URL}{prefix}/v1/thing"

    @patch.object(Client, "get_access_token", return_value="tok")
    @patch.object(Client, "_http_request")
    def test_dlp_uses_separate_base(self, mock_http: Mock, _tok: Mock, mock_client: Client) -> None:
        """DLP requests hit the separate DLP base URL, not the SCM base URL."""
        mock_client.http_request("GET", "/v2/api/dictionaries", use_dlp_base=True)

        _, kwargs = mock_http.call_args
        assert kwargs["full_url"] == f"{DEFAULT_DLP_BASE_URL}/v2/api/dictionaries"

    @patch.object(Client, "get_access_token", return_value="tok")
    @patch.object(Client, "_http_request")
    def test_custom_headers_merged(self, mock_http: Mock, _tok: Mock, mock_client: Client) -> None:
        """Caller-supplied headers override/extend the auth defaults."""
        mock_client.http_request(
            "PATCH", "/v1/thing", use_mgmt_base=True, headers={"Content-Type": "application/merge-patch+json"}
        )

        _, kwargs = mock_http.call_args
        assert kwargs["headers"]["Content-Type"] == "application/merge-patch+json"
        assert kwargs["headers"]["Authorization"] == "Bearer tok"

    @patch.object(Client, "get_access_token", return_value="tok")
    @patch.object(Client, "_http_request")
    def test_files_omit_json_content_type(self, mock_http: Mock, _tok: Mock, mock_client: Client) -> None:
        """Multipart uploads must not force application/json (boundary set by HTTP layer)."""
        mock_client.http_request("POST", "/v1/upload", use_mgmt_base=True, files={"file": ("n", b"x")})

        _, kwargs = mock_http.call_args
        assert "Content-Type" not in kwargs["headers"]


class TestScannerRequest:
    """API-key-authenticated runtime scanner transport."""

    @patch.object(Client, "_http_request")
    def test_success(self, mock_http: Mock, mock_client: Client) -> None:
        """Scanner request posts to the scanner base URL with the x-pan-token header."""
        mock_http.return_value = {"action": "allow"}

        result = mock_client.scanner_request({"contents": []})

        assert result == {"action": "allow"}
        _, kwargs = mock_http.call_args
        assert kwargs["full_url"] == f"{DEFAULT_SCANNER_BASE_URL}{SCANNER_SYNC_SCAN_PATH}"
        assert kwargs["headers"]["x-pan-token"] == "test_runtime_api_key_12345"

    def test_missing_api_key_raises(self) -> None:
        """Without a runtime API key, scanner requests fail with a clear error."""
        client = Client(base_url=BASE_URL)

        with pytest.raises(Exception, match="Runtime API Key is required"):
            client.scanner_request({"contents": []})


class TestTestModule:
    """Shared plane-agnostic connectivity check."""

    @patch.object(Client, "get_access_token", return_value="tok")
    def test_ok(self, mock_get_token: Mock, mock_client: Client) -> None:
        """A successful token fetch returns 'ok'."""
        assert run_test_module(mock_client) == "ok"
        mock_get_token.assert_called_once()

    @patch.object(Client, "get_access_token", side_effect=Exception("Authentication failed"))
    def test_failure(self, _mock_get_token: Mock, mock_client: Client) -> None:
        """A failed token fetch returns a descriptive error string."""
        result = run_test_module(mock_client)

        assert "Test failed" in result
        assert "Authentication failed" in result
