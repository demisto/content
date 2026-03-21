"""Unit tests for AtlassianApiModule."""

import time
from unittest.mock import MagicMock, patch

import pytest

from AtlassianApiModule import (
    ConfluenceCloudOAuthClient,
    JiraCloudOAuthClient,
    JiraOnPremOAuthClient,
    create_atlassian_oauth_client,
    create_jira_oauth_client,
)


class TestJiraCloudOAuthClient:
    """Test cases for JiraCloudOAuthClient."""

    @pytest.fixture
    def oauth_client(self):
        """Create a test OAuth client."""
        return JiraCloudOAuthClient(
            client_id="test-client-id",
            client_secret="test-client-secret",
            callback_url="https://localhost/callback",
            cloud_id="test-cloud-id",
            verify=True,
            proxy=False,
        )

    def test_get_oauth_scopes(self, oauth_client):
        """Test that correct OAuth scopes are returned."""
        scopes = oauth_client.get_oauth_scopes()
        assert "read:audit-log:jira" in scopes
        assert "manage:jira-configuration" in scopes
        assert "read:jira-user" in scopes
        assert "offline_access" in scopes

    @patch("AtlassianApiModule.get_integration_context")
    def test_get_access_token_valid(self, mock_get_context, oauth_client):
        """Test getting a valid access token that hasn't expired."""
        mock_get_context.return_value = {
            "token": "valid-access-token",
            "valid_until": time.time() + 3600,  # Valid for 1 hour
            "refresh_token": "refresh-token",
        }

        token = oauth_client.get_access_token()

        assert token == "valid-access-token"

    @patch("AtlassianApiModule.get_integration_context")
    def test_get_access_token_missing(self, mock_get_context, oauth_client):
        """Test error when no access token is configured."""
        mock_get_context.return_value = {}

        with pytest.raises(Exception) as exc_info:
            oauth_client.get_access_token()

        assert "No access token configured" in str(exc_info.value)

    @patch("AtlassianApiModule.get_integration_context")
    def test_get_access_token_missing_refresh_token(self, mock_get_context, oauth_client):
        """Test error when token is expired and no refresh token is available."""
        mock_get_context.return_value = {
            "token": "expired-token",
            "valid_until": time.time() - 100,  # Expired
            "refresh_token": "",
        }

        with pytest.raises(Exception) as exc_info:
            oauth_client.get_access_token()

        assert "No refresh token configured" in str(exc_info.value)

    @patch("AtlassianApiModule.get_integration_context")
    @patch("AtlassianApiModule.set_integration_context")
    @patch("requests.post")
    def test_get_access_token_expired_refresh(self, mock_post, mock_set_context, mock_get_context, oauth_client):
        """Test automatic token refresh when token is expired."""
        # Mock refresh token response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "scope": "read:audit-log:jira read:jira-user offline_access",
        }
        mock_post.return_value = mock_response

        # First call returns expired token, second call returns new token after refresh
        mock_get_context.side_effect = [
            {"token": "expired-token", "valid_until": time.time() - 100, "refresh_token": "refresh-token"},
            {"token": "expired-token", "valid_until": time.time() - 100, "refresh_token": "refresh-token"},
            {"token": "new-access-token", "valid_until": time.time() + 3600, "refresh_token": "new-refresh-token"},
        ]

        token = oauth_client.get_access_token()

        assert token == "new-access-token"
        mock_post.assert_called_once()
        mock_set_context.assert_called_once()

    @patch("requests.post")
    @patch("AtlassianApiModule.set_integration_context")
    @patch("AtlassianApiModule.get_integration_context")
    def test_oauth2_retrieve_access_token_with_code(self, mock_get_context, mock_set_context, mock_post, oauth_client):
        """Test retrieving access token with authorization code."""
        mock_get_context.return_value = {}

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "scope": "read:audit-log:jira",
        }
        mock_post.return_value = mock_response

        oauth_client.oauth2_retrieve_access_token(code="auth-code")

        # Verify POST was called with correct parameters
        call_args = mock_post.call_args
        assert call_args[1]["data"]["code"] == "auth-code"
        assert call_args[1]["data"]["grant_type"] == "authorization_code"
        assert call_args[1]["data"]["client_id"] == "test-client-id"

        # Verify context was updated
        mock_set_context.assert_called_once()
        context_arg = mock_set_context.call_args[0][0]
        assert context_arg["token"] == "new-access-token"
        assert context_arg["refresh_token"] == "new-refresh-token"

    @patch("requests.post")
    @patch("AtlassianApiModule.set_integration_context")
    @patch("AtlassianApiModule.get_integration_context")
    def test_oauth2_retrieve_access_token_with_refresh_token(self, mock_get_context, mock_set_context, mock_post, oauth_client):
        """Test retrieving access token with refresh token."""
        mock_get_context.return_value = {}

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "refreshed-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "scope": "read:audit-log:jira",
        }
        mock_post.return_value = mock_response

        oauth_client.oauth2_retrieve_access_token(refresh_token="old-refresh-token")

        # Verify POST was called with correct parameters
        call_args = mock_post.call_args
        assert call_args[1]["data"]["refresh_token"] == "old-refresh-token"
        assert call_args[1]["data"]["grant_type"] == "refresh_token"
        assert "code" not in call_args[1]["data"]

    def test_oauth2_retrieve_access_token_both_params(self, oauth_client):
        """Test error when both code and refresh_token are provided."""
        with pytest.raises(Exception) as exc_info:
            oauth_client.oauth2_retrieve_access_token(code="auth-code", refresh_token="refresh-token")

        assert "Both authorization code and refresh token" in str(exc_info.value)

    def test_oauth2_retrieve_access_token_no_params(self, oauth_client):
        """Test error when neither code nor refresh_token are provided."""
        with pytest.raises(Exception) as exc_info:
            oauth_client.oauth2_retrieve_access_token()

        assert "No authorization code or refresh token" in str(exc_info.value)

    @patch("requests.post")
    def test_oauth2_retrieve_access_token_http_error(self, mock_post, oauth_client):
        """Test error handling when token endpoint returns HTTP error."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Invalid client credentials"
        mock_response.raise_for_status.side_effect = __import__("requests").exceptions.HTTPError(response=mock_response)
        mock_post.return_value = mock_response

        with pytest.raises(Exception) as exc_info:
            oauth_client.oauth2_retrieve_access_token(code="bad-code")

        assert "Failed to retrieve OAuth token" in str(exc_info.value)

    @patch("AtlassianApiModule.set_integration_context")
    @patch("AtlassianApiModule.get_integration_context")
    def test_oauth_start(self, mock_get_context, mock_set_context, oauth_client):
        """Test OAuth start flow builds correct authorization URL."""
        mock_get_context.return_value = {}

        url = oauth_client.oauth_start()

        assert "https://auth.atlassian.com/authorize" in url
        assert "client_id=test-client-id" in url
        assert "redirect_uri=" in url
        assert "read%3Aaudit-log%3Ajira" in url or "read:audit-log:jira" in url
        assert "response_type=code" in url
        assert "state=" in url

        # Verify state was stored in integration context
        mock_set_context.assert_called_once()
        context_arg = mock_set_context.call_args[0][0]
        assert "oauth_state" in context_arg

    @patch.object(JiraCloudOAuthClient, "oauth2_retrieve_access_token")
    def test_oauth_complete(self, mock_retrieve, oauth_client):
        """Test OAuth complete flow."""
        oauth_client.oauth_complete(code="auth-code")

        mock_retrieve.assert_called_once_with(code="auth-code")

    @patch.object(JiraCloudOAuthClient, "get_access_token")
    def test_test_connection_success(self, mock_get_token, oauth_client):
        """Test successful connection test."""
        mock_get_token.return_value = "valid-token"

        # Should not raise exception
        oauth_client.test_connection()

        mock_get_token.assert_called_once()

    @patch.object(JiraCloudOAuthClient, "get_access_token")
    def test_test_connection_failure(self, mock_get_token, oauth_client):
        """Test failed connection test."""
        mock_get_token.side_effect = Exception("No token")

        with pytest.raises(Exception) as exc_info:
            oauth_client.test_connection()

        assert "No token" in str(exc_info.value)


class TestConfluenceCloudOAuthClient:
    """Test cases for ConfluenceCloudOAuthClient."""

    @pytest.fixture
    def oauth_client(self):
        """Create a test Confluence OAuth client."""
        return ConfluenceCloudOAuthClient(
            client_id="test-client-id",
            client_secret="test-client-secret",
            callback_url="https://localhost/callback",
            cloud_id="test-cloud-id",
            verify=True,
            proxy=False,
        )

    def test_get_oauth_scopes(self, oauth_client):
        """Test that correct Confluence OAuth scopes are returned."""
        scopes = oauth_client.get_oauth_scopes()
        assert "read:audit-log:confluence" in scopes
        assert "read:confluence-content.all" in scopes
        assert "read:confluence-space.summary" in scopes
        assert "read:confluence-user" in scopes
        assert "read:confluence-groups" in scopes
        assert "write:confluence-content" in scopes
        assert "write:confluence-space" in scopes
        assert "offline_access" in scopes

    @patch("AtlassianApiModule.get_integration_context")
    def test_get_access_token_valid(self, mock_get_context, oauth_client):
        """Test getting a valid access token for Confluence."""
        mock_get_context.return_value = {
            "token": "valid-confluence-token",
            "valid_until": time.time() + 3600,
            "refresh_token": "refresh-token",
        }

        token = oauth_client.get_access_token()
        assert token == "valid-confluence-token"

    @patch("AtlassianApiModule.get_integration_context")
    def test_get_access_token_missing(self, mock_get_context, oauth_client):
        """Test error when no Confluence access token is configured."""
        mock_get_context.return_value = {}

        with pytest.raises(Exception) as exc_info:
            oauth_client.get_access_token()

        assert "No access token configured" in str(exc_info.value)

    @patch("requests.post")
    @patch("AtlassianApiModule.set_integration_context")
    @patch("AtlassianApiModule.get_integration_context")
    def test_oauth2_retrieve_access_token_with_code(self, mock_get_context, mock_set_context, mock_post, oauth_client):
        """Test retrieving Confluence access token with authorization code."""
        mock_get_context.return_value = {}

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "confluence-access-token",
            "refresh_token": "confluence-refresh-token",
            "expires_in": 3600,
            "scope": "read:audit-log:confluence",
        }
        mock_post.return_value = mock_response

        oauth_client.oauth2_retrieve_access_token(code="auth-code")

        call_args = mock_post.call_args
        assert call_args[1]["data"]["code"] == "auth-code"
        assert call_args[1]["data"]["grant_type"] == "authorization_code"

        mock_set_context.assert_called_once()
        context_arg = mock_set_context.call_args[0][0]
        assert context_arg["token"] == "confluence-access-token"

    @patch("AtlassianApiModule.set_integration_context")
    @patch("AtlassianApiModule.get_integration_context")
    def test_oauth_start(self, mock_get_context, mock_set_context, oauth_client):
        """Test Confluence OAuth start flow builds correct authorization URL."""
        mock_get_context.return_value = {}

        url = oauth_client.oauth_start()

        assert "https://auth.atlassian.com/authorize" in url
        assert "client_id=test-client-id" in url
        assert "response_type=code" in url

    def test_oauth2_retrieve_access_token_both_params(self, oauth_client):
        """Test error when both code and refresh_token are provided for Confluence."""
        with pytest.raises(Exception) as exc_info:
            oauth_client.oauth2_retrieve_access_token(code="auth-code", refresh_token="refresh-token")

        assert "Both authorization code and refresh token" in str(exc_info.value)

    def test_oauth2_retrieve_access_token_no_params(self, oauth_client):
        """Test error when neither code nor refresh_token are provided for Confluence."""
        with pytest.raises(Exception) as exc_info:
            oauth_client.oauth2_retrieve_access_token()

        assert "No authorization code or refresh token" in str(exc_info.value)


class TestJiraOnPremOAuthClient:
    """Test cases for JiraOnPremOAuthClient."""

    @pytest.fixture
    def onprem_client(self):
        """Create a test On-Prem OAuth client."""
        return JiraOnPremOAuthClient(
            client_id="test-client-id",
            client_secret="test-client-secret",
            callback_url="https://localhost/callback",
            server_url="https://jira.company.com",
            verify=True,
            proxy=False,
        )

    def test_get_oauth_scopes_onprem(self, onprem_client):
        """Test that correct OAuth scopes are returned for On-Prem."""
        scopes = onprem_client.get_oauth_scopes()
        assert scopes == ["ADMIN"]

    def test_server_url_trailing_slash_stripped(self):
        """Test that trailing slash is stripped from server URL."""
        client = JiraOnPremOAuthClient(
            client_id="test-id",
            client_secret="test-secret",
            callback_url="https://localhost/callback",
            server_url="https://jira.company.com/",
        )
        assert client.server_url == "https://jira.company.com"

    @patch("requests.get")
    @patch("AtlassianApiModule.get_integration_context")
    @patch("AtlassianApiModule.set_integration_context")
    def test_oauth_start_onprem(self, mock_set_context, mock_get_context, mock_get, onprem_client):
        """Test OAuth start flow for On-Prem with PKCE."""
        mock_get_context.return_value = {}
        mock_response = MagicMock()
        mock_response.url = "https://jira.company.com/rest/oauth2/latest/authorize?client_id=test&..."
        mock_get.return_value = mock_response

        url = onprem_client.oauth_start()

        assert "https://jira.company.com/rest/oauth2/latest/authorize" in url
        mock_get.assert_called_once()

        # Verify PKCE code_verifier was stored
        mock_set_context.assert_called()
        # Get the first call (storing code_verifier)
        context = mock_set_context.call_args_list[0][0][0]
        assert "code_verifier" in context

        # Verify correct parameters were sent
        call_args = mock_get.call_args
        params = call_args[1]["params"]
        assert params["client_id"] == "test-client-id"
        assert params["code_challenge_method"] == "S256"
        assert "code_challenge" in params

    @patch("requests.get")
    @patch("AtlassianApiModule.get_integration_context")
    @patch("AtlassianApiModule.set_integration_context")
    def test_oauth_start_onprem_failure_cleans_code_verifier(self, mock_set_context, mock_get_context, mock_get, onprem_client):
        """Test that code_verifier is cleaned from context on oauth_start failure."""
        mock_get_context.return_value = {}
        mock_get.side_effect = Exception("Connection failed")

        with pytest.raises(Exception):
            onprem_client.oauth_start()

        # Verify code_verifier was cleaned up - last call should not have code_verifier
        last_call_context = mock_set_context.call_args_list[-1][0][0]
        assert "code_verifier" not in last_call_context

    @patch("requests.get")
    @patch("AtlassianApiModule.get_integration_context")
    @patch("AtlassianApiModule.set_integration_context")
    def test_oauth_start_onprem_no_url_cleans_code_verifier(self, mock_set_context, mock_get_context, mock_get, onprem_client):
        """Test that code_verifier is cleaned when no URL is returned."""
        mock_get_context.return_value = {}
        mock_response = MagicMock()
        mock_response.url = None
        mock_get.return_value = mock_response

        with pytest.raises(Exception) as exc_info:
            onprem_client.oauth_start()

        assert "No authorization URL" in str(exc_info.value)
        # Verify code_verifier was cleaned up
        last_call_context = mock_set_context.call_args_list[-1][0][0]
        assert "code_verifier" not in last_call_context

    @patch("requests.post")
    @patch("AtlassianApiModule.set_integration_context")
    @patch("AtlassianApiModule.get_integration_context")
    def test_oauth2_retrieve_access_token_onprem_with_code(self, mock_get_context, mock_set_context, mock_post, onprem_client):
        """Test retrieving access token with authorization code for On-Prem."""
        mock_get_context.return_value = {"code_verifier": "test-verifier"}

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "scope": "ADMIN",
        }
        mock_post.return_value = mock_response

        onprem_client.oauth2_retrieve_access_token(code="auth-code")

        # Verify POST was called with correct parameters including code_verifier
        call_args = mock_post.call_args
        assert call_args[1]["data"]["code"] == "auth-code"
        assert call_args[1]["data"]["code_verifier"] == "test-verifier"
        assert call_args[1]["data"]["grant_type"] == "authorization_code"

        # Verify code_verifier was removed from context
        context_arg = mock_set_context.call_args[0][0]
        assert "code_verifier" not in context_arg
        assert context_arg["token"] == "new-access-token"

    @patch("requests.post")
    @patch("AtlassianApiModule.set_integration_context")
    @patch("AtlassianApiModule.get_integration_context")
    def test_oauth2_retrieve_access_token_onprem_with_refresh(self, mock_get_context, mock_set_context, mock_post, onprem_client):
        """Test retrieving access token with refresh token for On-Prem."""
        mock_get_context.return_value = {}

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "refreshed-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "scope": "ADMIN",
        }
        mock_post.return_value = mock_response

        onprem_client.oauth2_retrieve_access_token(refresh_token="old-refresh-token")

        # Verify POST was called without code_verifier for refresh
        call_args = mock_post.call_args
        assert call_args[1]["data"]["refresh_token"] == "old-refresh-token"
        assert call_args[1]["data"]["grant_type"] == "refresh_token"

    @patch("requests.post")
    @patch("AtlassianApiModule.get_integration_context")
    def test_oauth2_retrieve_access_token_onprem_http_error(self, mock_get_context, mock_post, onprem_client):
        """Test error handling when On-Prem token endpoint returns HTTP error."""
        mock_get_context.return_value = {"code_verifier": "test-verifier"}

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_response.raise_for_status.side_effect = __import__("requests").exceptions.HTTPError(response=mock_response)
        mock_post.return_value = mock_response

        with pytest.raises(Exception) as exc_info:
            onprem_client.oauth2_retrieve_access_token(code="bad-code")

        assert "Failed to retrieve On-Prem OAuth token" in str(exc_info.value)

    def test_oauth2_retrieve_access_token_onprem_both_params(self, onprem_client):
        """Test error when both code and refresh_token are provided for On-Prem."""
        with pytest.raises(Exception) as exc_info:
            onprem_client.oauth2_retrieve_access_token(code="auth-code", refresh_token="refresh-token")

        assert "Both authorization code and refresh token" in str(exc_info.value)

    def test_oauth2_retrieve_access_token_onprem_no_params(self, onprem_client):
        """Test error when neither code nor refresh_token are provided for On-Prem."""
        with pytest.raises(Exception) as exc_info:
            onprem_client.oauth2_retrieve_access_token()

        assert "No authorization code or refresh token" in str(exc_info.value)


class TestFactoryFunction:
    """Test the factory function."""

    def test_create_jira_cloud_client(self):
        """Test creating Jira Cloud OAuth client via factory function."""
        client = create_atlassian_oauth_client(
            client_id="test-id",
            client_secret="test-secret",
            callback_url="https://localhost/callback",
            cloud_id="cloud-123",
            verify=True,
            proxy=False,
        )

        assert isinstance(client, JiraCloudOAuthClient)
        assert client.client_id == "test-id"
        assert client.client_secret == "test-secret"
        assert client.callback_url == "https://localhost/callback"
        assert client.cloud_id == "cloud-123"
        assert client.verify is True
        assert client.proxy is False

    def test_create_jira_onprem_client(self):
        """Test creating On-Prem OAuth client via factory function."""
        client = create_atlassian_oauth_client(
            client_id="test-id",
            client_secret="test-secret",
            callback_url="https://localhost/callback",
            cloud_id="",  # Empty for on-prem
            server_url="https://jira.company.com",
            verify=True,
            proxy=False,
        )

        assert isinstance(client, JiraOnPremOAuthClient)
        assert client.client_id == "test-id"
        assert client.server_url == "https://jira.company.com"

    def test_create_confluence_cloud_client(self):
        """Test creating Confluence Cloud OAuth client via factory function."""
        client = create_atlassian_oauth_client(
            client_id="test-id",
            client_secret="test-secret",
            callback_url="https://localhost/callback",
            cloud_id="cloud-123",
            product="confluence",
            verify=True,
            proxy=False,
        )

        assert isinstance(client, ConfluenceCloudOAuthClient)
        assert client.client_id == "test-id"
        assert client.cloud_id == "cloud-123"

    def test_create_confluence_cloud_client_case_insensitive(self):
        """Test that product parameter is case-insensitive."""
        client = create_atlassian_oauth_client(
            client_id="test-id",
            client_secret="test-secret",
            callback_url="https://localhost/callback",
            cloud_id="cloud-123",
            product="Confluence",
        )

        assert isinstance(client, ConfluenceCloudOAuthClient)

    def test_create_default_jira_client_when_product_not_specified(self):
        """Test that Jira client is created by default when product is not specified."""
        client = create_atlassian_oauth_client(
            client_id="test-id",
            client_secret="test-secret",
            callback_url="https://localhost/callback",
            cloud_id="cloud-123",
        )

        assert isinstance(client, JiraCloudOAuthClient)

    def test_create_onprem_client_ignores_product(self):
        """Test that On-Prem always creates JiraOnPremOAuthClient regardless of product."""
        client = create_atlassian_oauth_client(
            client_id="test-id",
            client_secret="test-secret",
            callback_url="https://localhost/callback",
            cloud_id="",
            server_url="https://jira.company.com",
            product="confluence",
        )

        # On-Prem currently only supports Jira
        assert isinstance(client, JiraOnPremOAuthClient)

    def test_create_jira_oauth_client_alias(self):
        """Test that create_jira_oauth_client is a backward-compatible alias."""
        assert create_jira_oauth_client is create_atlassian_oauth_client

    def test_create_jira_oauth_client_alias_creates_cloud_client(self):
        """Test that the alias function creates the correct client type."""
        client = create_jira_oauth_client(
            client_id="test-id",
            client_secret="test-secret",
            callback_url="https://localhost/callback",
            cloud_id="cloud-123",
        )
        assert isinstance(client, JiraCloudOAuthClient)

    def test_create_jira_oauth_client_alias_creates_onprem_client(self):
        """Test that the alias function creates On-Prem client when no cloud_id."""
        client = create_jira_oauth_client(
            client_id="test-id",
            client_secret="test-secret",
            callback_url="https://localhost/callback",
            cloud_id="",
            server_url="https://jira.company.com",
        )
        assert isinstance(client, JiraOnPremOAuthClient)


class TestConfluenceOAuthBadPaths:
    """Bad path tests for Confluence OAuth client."""

    @pytest.fixture
    def oauth_client(self):
        """Create a test Confluence OAuth client."""
        return ConfluenceCloudOAuthClient(
            client_id="test-client-id",
            client_secret="test-client-secret",
            callback_url="https://localhost/callback",
            cloud_id="test-cloud-id",
            verify=True,
            proxy=False,
        )

    @patch("requests.post")
    def test_confluence_oauth2_retrieve_access_token_http_error(self, mock_post, oauth_client):
        """Test error handling when Confluence token endpoint returns HTTP error."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Invalid client credentials"
        mock_response.raise_for_status.side_effect = __import__("requests").exceptions.HTTPError(response=mock_response)
        mock_post.return_value = mock_response

        with pytest.raises(Exception) as exc_info:
            oauth_client.oauth2_retrieve_access_token(code="bad-code")

        assert "Failed to retrieve OAuth token" in str(exc_info.value)

    @patch("requests.post")
    def test_confluence_oauth2_retrieve_access_token_connection_error(self, mock_post, oauth_client):
        """Test error handling when Confluence token endpoint is unreachable."""
        mock_post.side_effect = __import__("requests").exceptions.ConnectionError("Connection refused")

        with pytest.raises(Exception) as exc_info:
            oauth_client.oauth2_retrieve_access_token(code="auth-code")

        assert "Failed to connect to OAuth token endpoint" in str(exc_info.value)

    @patch("AtlassianApiModule.get_integration_context")
    def test_confluence_get_access_token_expired_no_refresh(self, mock_get_context, oauth_client):
        """Test error when Confluence token is expired and no refresh token."""
        mock_get_context.return_value = {"token": "expired-token", "valid_until": time.time() - 100, "refresh_token": ""}

        with pytest.raises(Exception) as exc_info:
            oauth_client.get_access_token()

        assert "No refresh token configured" in str(exc_info.value)

    @patch("AtlassianApiModule.set_integration_context")
    @patch("AtlassianApiModule.get_integration_context")
    def test_confluence_oauth_start(self, mock_get_context, mock_set_context, oauth_client):
        """Test Confluence OAuth start generates correct URL with state."""
        mock_get_context.return_value = {}

        url = oauth_client.oauth_start()

        assert "https://auth.atlassian.com/authorize" in url
        assert "client_id=test-client-id" in url
        assert "state=" in url
        assert "response_type=code" in url

        # Verify state was stored
        mock_set_context.assert_called_once()
        context_arg = mock_set_context.call_args[0][0]
        assert "oauth_state" in context_arg

    @patch.object(ConfluenceCloudOAuthClient, "oauth2_retrieve_access_token")
    def test_confluence_oauth_complete(self, mock_retrieve, oauth_client):
        """Test Confluence OAuth complete flow."""
        oauth_client.oauth_complete(code="auth-code")
        mock_retrieve.assert_called_once_with(code="auth-code")

    @patch.object(ConfluenceCloudOAuthClient, "get_access_token")
    def test_confluence_test_connection_success(self, mock_get_token, oauth_client):
        """Test successful Confluence connection test."""
        mock_get_token.return_value = "valid-token"
        oauth_client.test_connection()
        mock_get_token.assert_called_once()

    @patch.object(ConfluenceCloudOAuthClient, "get_access_token")
    def test_confluence_test_connection_failure(self, mock_get_token, oauth_client):
        """Test failed Confluence connection test."""
        mock_get_token.side_effect = Exception("No token")

        with pytest.raises(Exception) as exc_info:
            oauth_client.test_connection()

        assert "No token" in str(exc_info.value)


class TestOnPremOAuthBadPaths:
    """Additional bad path tests for On-Prem OAuth client."""

    @pytest.fixture
    def onprem_client(self):
        """Create a test On-Prem OAuth client."""
        return JiraOnPremOAuthClient(
            client_id="test-client-id",
            client_secret="test-client-secret",
            callback_url="https://localhost/callback",
            server_url="https://jira.company.com",
            verify=True,
            proxy=False,
        )

    @patch("requests.post")
    @patch("AtlassianApiModule.get_integration_context")
    def test_onprem_oauth2_connection_error(self, mock_get_context, mock_post, onprem_client):
        """Test error handling when On-Prem token endpoint is unreachable."""
        mock_get_context.return_value = {"code_verifier": "test-verifier"}
        mock_post.side_effect = __import__("requests").exceptions.ConnectionError("Connection refused")

        with pytest.raises(Exception) as exc_info:
            onprem_client.oauth2_retrieve_access_token(code="auth-code")

        assert "Failed to connect to On-Prem OAuth token endpoint" in str(exc_info.value)
