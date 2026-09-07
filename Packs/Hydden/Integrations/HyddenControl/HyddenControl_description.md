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

### Troubleshooting

- If the integration reports an authorization error, verify that the Client ID and Client Secret belong to an enabled API user with `rest_api` access.
- If the integration reports a TLS error, verify the certificate chain on the Hydden API URL. Use **Trust any certificate (not secure)** only for temporary testing.
- If the connection requires an outbound proxy, enable **Use system proxy settings**.
- A cold `hydden-blast-radius` request can take several minutes while Hydden builds the tenant reachability graph. Increase **HTTP request timeout (seconds)** if the request times out.
- If a playbook reports a missing `account_id`, confirm that the Cortex XSIAM issue contains `alert.user_name`, or supply the **AccountId** input in the Playbook Debugger.
