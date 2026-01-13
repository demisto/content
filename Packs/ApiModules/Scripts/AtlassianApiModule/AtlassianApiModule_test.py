"""Unit tests for AtlassianApiModule."""
import time
from unittest.mock import MagicMock, patch

import pytest

from AtlassianApiModule import (
    JiraCloudOAuthClient,
    JiraOnPremOAuthClient,
    create_jira_oauth_client,
    create_atlassian_oauth_client
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
            proxy=False
        )

    def test_get_oauth_scopes(self, oauth_client):
        """Test that correct OAuth scopes are returned."""
        scopes = oauth_client.get_oauth_scopes()
        assert "read:audit-log:jira" in scopes
        assert "read:jira-user" in scopes
        assert "offline_access" in scopes

    @patch('JiraApiModule.get_integration_context')
    @patch('JiraApiModule.set_integration_context')
    def test_get_access_token_valid(self, mock_set_context, mock_get_context, oauth_client):
        """Test getting a valid access token that hasn't expired."""
        mock_get_context.return_value = {
            "token": "valid-access-token",
            "valid_until": time.time() + 3600,  # Valid for 1 hour
            "refresh_token": "refresh-token"
        }
        
        token = oauth_client.get_access_token()
        
        assert token == "valid-access-token"
        # Should not call set_integration_context since token is still valid
        mock_set_context.assert_not_called()

    @patch('AtlassianApiModule.get_integration_context')
    def test_get_access_token_missing(self, mock_get_context, oauth_client):
        """Test error when no access token is configured."""
        mock_get_context.return_value = {}
        
        with pytest.raises(Exception) as exc_info:
            oauth_client.get_access_token()
        
        assert "No access token configured" in str(exc_info.value)

    @patch('AtlassianApiModule.get_integration_context')
    @patch('AtlassianApiModule.set_integration_context')
    @patch('requests.post')
    def test_get_access_token_expired_refresh(
        self, mock_post, mock_set_context, mock_get_context, oauth_client
    ):
        """Test automatic token refresh when token is expired."""
        # Mock expired token
        mock_get_context.return_value = {
            "token": "expired-token",
            "valid_until": time.time() - 100,  # Expired
            "refresh_token": "refresh-token"
        }
        
        # Mock refresh token response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "scope": "read:audit-log:jira read:jira-user offline_access"
        }
        mock_post.return_value = mock_response
        
        # Second call to get_integration_context should return new token
        mock_get_context.side_effect = [
            {
                "token": "expired-token",
                "valid_until": time.time() - 100,
                "refresh_token": "refresh-token"
            },
            {
                "token": "new-access-token",
                "valid_until": time.time() + 3600,
                "refresh_token": "new-refresh-token"
            }
        ]
        
        token = oauth_client.get_access_token()
        
        assert token == "new-access-token"
        mock_post.assert_called_once()
        mock_set_context.assert_called_once()

    @patch('requests.post')
    @patch('JiraApiModule.set_integration_context')
    @patch('JiraApiModule.get_integration_context')
    def test_oauth2_retrieve_access_token_with_code(
        self, mock_get_context, mock_set_context, mock_post, oauth_client
    ):
        """Test retrieving access token with authorization code."""
        mock_get_context.return_value = {}
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "scope": "read:audit-log:jira"
        }
        mock_post.return_value = mock_response
        
        oauth_client.oauth2_retrieve_access_token(code="auth-code")
        
        # Verify POST was called with correct parameters
        call_args = mock_post.call_args
        assert call_args[1]['data']['code'] == "auth-code"
        assert call_args[1]['data']['grant_type'] == "authorization_code"
        assert call_args[1]['data']['client_id'] == "test-client-id"
        
        # Verify context was updated
        mock_set_context.assert_called_once()
        context_arg = mock_set_context.call_args[0][0]
        assert context_arg['token'] == "new-access-token"
        assert context_arg['refresh_token'] == "new-refresh-token"

    @patch('requests.post')
    @patch('AtlassianApiModule.set_integration_context')
    @patch('AtlassianApiModule.get_integration_context')
    def test_oauth2_retrieve_access_token_with_refresh_token(
        self, mock_get_context, mock_set_context, mock_post, oauth_client
    ):
        """Test retrieving access token with refresh token."""
        mock_get_context.return_value = {}
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "refreshed-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "scope": "read:audit-log:jira"
        }
        mock_post.return_value = mock_response
        
        oauth_client.oauth2_retrieve_access_token(refresh_token="old-refresh-token")
        
        # Verify POST was called with correct parameters
        call_args = mock_post.call_args
        assert call_args[1]['data']['refresh_token'] == "old-refresh-token"
        assert call_args[1]['data']['grant_type'] == "refresh_token"
        assert 'code' not in call_args[1]['data']

    def test_oauth2_retrieve_access_token_both_params(self, oauth_client):
        """Test error when both code and refresh_token are provided."""
        with pytest.raises(Exception) as exc_info:
            oauth_client.oauth2_retrieve_access_token(
                code="auth-code",
                refresh_token="refresh-token"
            )
        
        assert "Both authorization code and refresh token" in str(exc_info.value)

    def test_oauth2_retrieve_access_token_no_params(self, oauth_client):
        """Test error when neither code nor refresh_token are provided."""
        with pytest.raises(Exception) as exc_info:
            oauth_client.oauth2_retrieve_access_token()
        
        assert "No authorization code or refresh token" in str(exc_info.value)

    @patch('requests.get')
    def test_oauth_start(self, mock_get, oauth_client):
        """Test OAuth start flow."""
        mock_response = MagicMock()
        mock_response.url = "https://auth.atlassian.com/authorize?client_id=test&..."
        mock_get.return_value = mock_response
        
        url = oauth_client.oauth_start()
        
        assert "https://auth.atlassian.com/authorize" in url
        mock_get.assert_called_once()
        
        # Verify correct parameters were sent
        call_args = mock_get.call_args
        params = call_args[1]['params']
        assert params['client_id'] == "test-client-id"
        assert params['redirect_uri'] == "https://localhost/callback"
        assert "read:audit-log:jira" in params['scope']

    @patch('requests.get')
    def test_oauth_start_no_url(self, mock_get, oauth_client):
        """Test error when OAuth start returns no URL."""
        mock_response = MagicMock()
        mock_response.url = None
        mock_get.return_value = mock_response
        
        with pytest.raises(Exception) as exc_info:
            oauth_client.oauth_start()
        
        assert "No authorization URL" in str(exc_info.value)

    @patch.object(JiraCloudOAuthClient, 'oauth2_retrieve_access_token')
    def test_oauth_complete(self, mock_retrieve, oauth_client):
        """Test OAuth complete flow."""
        oauth_client.oauth_complete(code="auth-code")
        
        mock_retrieve.assert_called_once_with(code="auth-code")

    @patch.object(JiraCloudOAuthClient, 'get_access_token')
    def test_test_connection_success(self, mock_get_token, oauth_client):
        """Test successful connection test."""
        mock_get_token.return_value = "valid-token"
        
        # Should not raise exception
        oauth_client.test_connection()
        
        mock_get_token.assert_called_once()

    @patch.object(JiraCloudOAuthClient, 'get_access_token')
    def test_test_connection_failure(self, mock_get_token, oauth_client):
        """Test failed connection test."""
        mock_get_token.side_effect = Exception("No token")
        
        with pytest.raises(Exception) as exc_info:
            oauth_client.test_connection()
        
        assert "No token" in str(exc_info.value)


class TestFactoryFunction:
    """Test the factory function."""

    def test_create_jira_oauth_client(self):
        """Test creating OAuth client via factory function."""
        client = create_jira_oauth_client(
            client_id="test-id",
            client_secret="test-secret",
            callback_url="https://localhost/callback",
            cloud_id="cloud-123",
            verify=True,
            proxy=False
        )
        
        assert isinstance(client, JiraCloudOAuthClient)
        assert client.client_id == "test-id"
        assert client.client_secret == "test-secret"
        assert client.callback_url == "https://localhost/callback"
        assert client.cloud_id == "cloud-123"
        assert client.verify is True
        assert client.proxy is False

    def test_create_jira_oauth_client_onprem(self):
        """Test creating On-Prem OAuth client via factory function."""
        client = create_jira_oauth_client(
            client_id="test-id",
            client_secret="test-secret",
            callback_url="https://localhost/callback",
            cloud_id="",  # Empty for on-prem
            server_url="https://jira.company.com",
            verify=True,
            proxy=False
        )
        
        assert isinstance(client, JiraOnPremOAuthClient)
        assert client.client_id == "test-id"
        assert client.server_url == "https://jira.company.com"


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
            proxy=False
        )

    def test_get_oauth_scopes_onprem(self, onprem_client):
        """Test that correct OAuth scopes are returned for On-Prem."""
        scopes = onprem_client.get_oauth_scopes()
        assert scopes == ["WRITE"]

    @patch('requests.get')
    @patch('JiraApiModule.get_integration_context')
    @patch('JiraApiModule.set_integration_context')
    def test_oauth_start_onprem(
        self, mock_set_context, mock_get_context, mock_get, onprem_client
    ):
        """Test OAuth start flow for On-Prem with PKCE."""
        mock_get_context.return_value = {}
        mock_response = MagicMock()
        mock_response.url = "https://jira.company.com/rest/oauth2/latest/authorize?client_id=test&..."
        mock_get.return_value = mock_response
        
        url = onprem_client.oauth_start()
        
        assert "https://jira.company.com/rest/oauth2/latest/authorize" in url
        mock_get.assert_called_once()
        
        # Verify PKCE code_verifier was stored
        mock_set_context.assert_called_once()
        context = mock_set_context.call_args[0][0]
        assert "code_verifier" in context
        
        # Verify correct parameters were sent
        call_args = mock_get.call_args
        params = call_args[1]['params']
        assert params['client_id'] == "test-client-id"
        assert params['code_challenge_method'] == "S256"
        assert 'code_challenge' in params

    @patch('requests.post')
    @patch('AtlassianApiModule.set_integration_context')
    @patch('AtlassianApiModule.get_integration_context')
    def test_oauth2_retrieve_access_token_onprem_with_code(
        self, mock_get_context, mock_set_context, mock_post, onprem_client
    ):
        """Test retrieving access token with authorization code for On-Prem."""
        mock_get_context.return_value = {"code_verifier": "test-verifier"}
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "scope": "WRITE"
        }
        mock_post.return_value = mock_response
        
        onprem_client.oauth2_retrieve_access_token(code="auth-code")
        
        # Verify POST was called with correct parameters including code_verifier
        call_args = mock_post.call_args
        assert call_args[1]['data']['code'] == "auth-code"
        assert call_args[1]['data']['code_verifier'] == "test-verifier"
        assert call_args[1]['data']['grant_type'] == "authorization_code"
        
        # Verify code_verifier was removed from context
        context_arg = mock_set_context.call_args[0][0]
        assert "code_verifier" not in context_arg
        assert context_arg['token'] == "new-access-token"

    @patch('requests.post')
    @patch('JiraApiModule.set_integration_context')
    @patch('JiraApiModule.get_integration_context')
    def test_oauth2_retrieve_access_token_onprem_with_refresh(
        self, mock_get_context, mock_set_context, mock_post, onprem_client
    ):
        """Test retrieving access token with refresh token for On-Prem."""
        mock_get_context.return_value = {}
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "refreshed-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "scope": "WRITE"
        }
        mock_post.return_value = mock_response
        
        onprem_client.oauth2_retrieve_access_token(refresh_token="old-refresh-token")
        
        # Verify POST was called without code_verifier for refresh
        call_args = mock_post.call_args
        assert call_args[1]['data']['refresh_token'] == "old-refresh-token"
        assert call_args[1]['data']['grant_type'] == "refresh_token"
        assert call_args[1]['data']['code_verifier'] == ""