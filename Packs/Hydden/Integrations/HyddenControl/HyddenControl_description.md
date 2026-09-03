## Configure Hydden Control on Cortex XSIAM

This integration was integrated and tested with the Hydden Control public REST API (`/api/public/v1`).

### Get Hydden API credentials

1. Sign in to Hydden Control.
2. Create or select an API user that can call the public REST API (`rest_api`).
3. Copy the **Client ID** and **Client Secret**. The integration exchanges those values for an OAuth 2.0 client-credentials bearer token.

### Create the instance

1. Navigate to **Settings** > **Data Sources & Integrations**.
2. Search for **Hydden Control**.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Required** |
   | --- | --- |
   | Hydden API URL (e.g., https://control.hydden.ai/api/public/v1) | True |
   | Client ID / Client Secret | True |
   | HTTP request timeout (seconds) | False |
   | Trust any certificate (not secure) | False |
   | Use system proxy settings | False |

4. Set **Hydden API URL** to the public API root, for example `https://control.hydden.ai/api/public/v1`.
5. Enter the **Client ID** and **Client Secret**.
6. Optionally set **HTTP request timeout** (default `300` seconds). A cold blast-radius call can take several minutes; later calls are typically sub-second.
7. Click **Test** to validate the URL, credentials, and connection.
8. Click **Save & Exit** and leave the instance enabled.

`hydden-deprovision-account` is marked potentially harmful. Use it only for accounts you intend to disable across the Hydden identity fabric.
