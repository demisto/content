## LinkedIn Learning Event Collector

This section explains how to configure a **LinkedIn Learning** event collector instance in Cortex XSIAM.

### Prerequisites

- A LinkedIn Learning instance.
- Admin access to the LinkedIn Learning instance (required to generate an access token / provision API keys).

### Obtaining a Client ID and Client Secret

To generate an access token, you need admin access to a LinkedIn Learning instance.

1. Sign in to the LinkedIn Learning Admin portal.
2. Provision API keys for your account (**LinkedIn Learning Admin → API application**). See [Provision API Keys](https://learn.microsoft.com/en-us/linkedin/learning/getting-started/authentication#provision-api-keys).
3. Copy the generated **Client ID** and **Client Secret** and use them when configuring the instance.

### Configuration

| Parameter | Description |
|-----------|-------------|
| **Server URL** | The LinkedIn API base URL. Default: `https://api.linkedin.com`. This is a single global endpoint with no regional variants. |
| **Client ID** | The two-legged OAuth 2.0 Client ID from the LinkedIn Learning Admin API application. |
| **Client Secret** | The two-legged OAuth 2.0 Client Secret from the LinkedIn Learning Admin API application. |
| **Engagement metric type / qualifier, Asset type, Content source, Primary/Secondary aggregation criteria** | Advanced settings used to build the learning activity report query. |
| **Maximum number of events per fetch** | Maximum number of events to fetch per cycle (default: 1000; up to 100 per API page). |

### Authorization

This integration uses the **Two-legged OAuth 2.0 (Client Credentials)** flow. The integration automatically obtains and refreshes access tokens using the provided Client ID and Client Secret.

Note: the token endpoint host (`www.linkedin.com`) differs from the API host (`api.linkedin.com`). The integration derives the token endpoint from the configured Server URL automatically.

### API Documentation

For more information, see the [learningActivityReports API reference](https://learn.microsoft.com/en-us/linkedin/learning/reference/learning-activity-reports-reference).
