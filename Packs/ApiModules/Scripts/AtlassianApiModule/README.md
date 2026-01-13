# AtlassianApiModule

This API module provides shared OAuth 2.0 authentication functionality for Atlassian products (Jira, Confluence), supporting both Cloud and On-Prem/Data Center instances.

## Classes

### AtlassianOAuthClient (Abstract Base Class)

Base class for Atlassian OAuth 2.0 authentication with the following features:
- Access token management with automatic refresh
- OAuth 2.0 authorization flow
- Integration context storage for tokens

#### Methods

- `get_access_token()`: Retrieves valid access token, refreshing if needed
- `oauth2_retrieve_access_token(code, refresh_token)`: Exchanges code/refresh token for access token
- `oauth_start()`: Initiates OAuth flow and returns authorization URL
- `oauth_complete(code)`: Completes OAuth flow with authorization code
- `test_connection()`: Tests OAuth authentication

### JiraCloudOAuthClient

Concrete implementation for Jira Cloud with predefined scopes:
- `read:audit-log:jira`
- `read:jira-user`
- `offline_access`

### JiraOnPremOAuthClient

Concrete implementation for Jira On-Prem/Data Center with:
- PKCE (Proof Key for Code Exchange) support for enhanced security
- Scope: `WRITE` (provides read and write access)
- Server-specific OAuth endpoints

## Usage

### Jira Cloud

```python
from AtlassianApiModule import create_jira_oauth_client

# Create OAuth client for Cloud (backward compatible function name)
oauth_client = create_jira_oauth_client(
    client_id="your-client-id",
    client_secret="your-client-secret",
    callback_url="https://localhost/callback",
    cloud_id="your-cloud-id",  # Required for Cloud
    verify=True,
    proxy=False
)

# Start OAuth flow
auth_url = oauth_client.oauth_start()

# Complete OAuth flow (after user authorizes)
oauth_client.oauth_complete(code="authorization-code")

# Get access token for API calls
access_token = oauth_client.get_access_token()
```

### Jira On-Prem/Data Center

```python
from AtlassianApiModule import create_atlassian_oauth_client

# Create OAuth client for On-Prem
oauth_client = create_atlassian_oauth_client(
    client_id="your-client-id",
    client_secret="your-client-secret",
    callback_url="https://localhost/callback",
    cloud_id="",  # Empty for On-Prem
    server_url="https://jira.company.com",  # Your Jira server URL
    verify=True,
    proxy=False
)

# Start OAuth flow (uses PKCE)
auth_url = oauth_client.oauth_start()

# Complete OAuth flow (after user authorizes)
oauth_client.oauth_complete(code="authorization-code")

# Get access token for API calls
access_token = oauth_client.get_access_token()
```

## Integration with Atlassian Integrations

This module is designed to be imported by Atlassian product integrations that need OAuth 2.0 support:
- **Jira**: JiraEventCollector (supports both Cloud and On-Prem), JiraV3 (future refactoring)
- **Confluence**: Future integrations

The module handles all OAuth token lifecycle management, allowing integrations to focus on their core functionality.

## Function Names

- `create_atlassian_oauth_client()` - Generic factory function
- `create_jira_oauth_client()` - Backward compatibility alias (same as above)

## Key Features

- **Automatic Instance Detection**: Factory function automatically creates the correct client type based on `cloud_id` parameter
- **PKCE Support**: On-Prem implementation uses PKCE for enhanced security
- **Token Management**: Automatic token refresh with 10-second expiry buffer
- **Error Handling**: Comprehensive error messages for troubleshooting