## Cisco Meraki v2

See the vendor's documentation for more details [here](https://developer.cisco.com/meraki/api-v1/introduction/).

### Base URL

Use the URL of your Meraki dashboard cluster:

| Region | Base URL |
| --- | --- |
| North America, South America, Europe, Asia-Pacific | `https://api.meraki.com` (default) |
| Canada | `https://api.meraki.ca` |
| China | `https://api.meraki.cn` |
| India | `https://api.meraki.in` |
| United States FedRAMP | `https://api.gov-meraki.com` |

### Authentication

Configure **one** of the following methods. When both are configured, OAuth 2.0 is used.

#### OAuth 2.0 (recommended, `https://api.meraki.com` only)

1. In the Meraki Dashboard, go to **Organization** > **Integrations** > **My integrations** and register a new integration.
2. Set a **Redirect URI** (for example, `https://localhost`) and grant these scopes: `dashboard:general:config:read`, `dashboard:general:config:write`, `dashboard:general:telemetry:read`, `dashboard:iam:config:read`, `dashboard:licensing:config:read`, `dashboard:licensing:config:write`, `sdwan:config:read`, `sdwan:config:write`, `wireless:config:read`.
3. Enter the **Client ID**, **Client Secret** and **Redirect URI** in the instance and save it.
4. Run `!meraki-generate-login-url`, open the URL, sign in and approve access.
5. Copy the `code` value from the URL you are redirected to, paste it into **Authorization code**, and save the instance.
6. Run `!meraki-auth-test`.

To authorize again, run `!meraki-auth-reset` and repeat steps 4–6.

#### API Key (all clusters)

1. Open your Meraki dashboard and go to **Organization** > **Settings**.
2. Make sure API access is set to **Enable access to the Cisco Meraki Dashboard API**.
3. Click your account email address (upper-right) > **My profile**, and generate an API key.
4. Enter it in **API Key** and click **Test**.
