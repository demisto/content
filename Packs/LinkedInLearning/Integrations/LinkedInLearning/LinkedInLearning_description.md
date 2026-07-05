## LinkedIn Learning Event Collector

This section explains how to configure a **LinkedIn Learning** event collector instance in Cortex XSIAM.

### Prerequisites

- A LinkedIn Learning Enterprise account with API access enabled.
- Admin access to the LinkedIn Learning Admin portal.

### Obtaining Client ID and Client Secret

1. Navigate to the [LinkedIn Developer Portal](https://www.linkedin.com/developers/).
2. Create a new application or select an existing one.
3. Under the **Auth** tab, locate the **Client ID** and **Client Secret**.
4. Ensure the application has the `r_liteprofile` and `r_organization_social` permissions, as well as the **Learning Activity Reports API** product enabled.

### Configuration

| Parameter | Description |
|-----------|-------------|
| **Server URL** | The LinkedIn API base URL. Default: `https://api.linkedin.com` |
| **Client ID** | The OAuth 2.0 Client ID from your LinkedIn Developer application. |
| **Client Secret** | The OAuth 2.0 Client Secret from your LinkedIn Developer application. |
| **Learning activity report filter** | Query parameters for filtering learning activity reports. |
| **Max events per fetch** | Maximum number of events to fetch per cycle (default: 1000). |

### Authorization

This integration uses the **Two-legged OAuth 2.0 (Client Credentials)** flow. The integration automatically obtains and refreshes access tokens using the provided Client ID and Client Secret.

### API Documentation

For more information, see the [LinkedIn Learning API documentation](https://learn.microsoft.com/en-us/linkedin/learning/).
