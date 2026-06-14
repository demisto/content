## Proofpoint Cloud Threat Response

Use this integration to fetch incidents from Proofpoint Cloud Threat Response (CTR) into Cortex XSOAR and to retrieve incident details on-demand.

### Prerequisites

Before configuring the integration, verify you have the following:

- **Proofpoint API credentials**: A valid **Client ID** and **Client Secret** generated from your Proofpoint Threat Response account. These credentials are used to obtain a Bearer token from `https://auth.proofpoint.com/v1/token` using the OAuth2 `client_credentials` grant.
- **API root URL**: The endpoint for your Proofpoint Cloud Threat Response instance. The default is `https://threatprotection-api.proofpoint.com`.

For details on generating API credentials, see [API Key Management](https://help.proofpoint.com/Admin_Portal/Settings/API_Key_Management).
