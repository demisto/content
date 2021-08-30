Use the CrowdStrike OpenAPI integration to interact with CrowdStrike APIs that do not have dedicated integrations in Cortex XSOAR, for example, CrowdStrike FalconX, etc.

To use the CrowdStrike OpenAPI integration, you need the ID and secret of an API client that has right scopes granted to it.

For more details, refer to the [CrowdStrike OAuth2-Based APIs documentation](https://falcon.crowdstrike.com/support/documentation/46/crowdstrike-oauth2-based-apis).

*Note:* The integration is in ***beta*** as it was auto generated from the CrowdStrike Falcon OpenAPI specification and is not fully tested.

## Configure CrowdStrike OpenAPI on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CrowdStrike OpenAPI.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Cloud Base URL | True |
    | Client ID | True |
    | Client Secret | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.
