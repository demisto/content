Integrate RetarusSecureEmailGateway to seamlessly fetch events and enhance email security.

## Configure RetarusSecureEmailGateway Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RetarusSecureEmailGateway.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** | **Description** |
    | --- | --- | --- |
    | Server URL | True | |
    | Token ID | True | |
    | Channel name | False | The channel to fetch events from |
    | Fetch interval in seconds | True | |
    | Trust any certificate (not secure) | False |

5. No test button option available due to API limitation. Save the configured instance to test the connection. If you encounter an 'Authentication failed' error, check your configuration.
