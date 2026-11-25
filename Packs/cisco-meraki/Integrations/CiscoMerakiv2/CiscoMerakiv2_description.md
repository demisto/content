## Cisco Meraki v2

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

Select the method in **Authentication Method** (default: **API Key**).

#### OAuth 2.0 (recommended, `https://api.meraki.com` only)

1. Sign in to the Cisco integration registry at [https://integrate.cisco.com/login](https://integrate.cisco.com/login) and create a new integration.
2. Set a **Redirect URI** (for example, `https://localhost`) and select these scopes: `dashboard:general:config:read`, `dashboard:general:config:write`, `dashboard:general:telemetry:read`, `dashboard:iam:config:read`, `dashboard:licensing:config:read`, `dashboard:licensing:config:write`, `sdwan:config:read`, `sdwan:config:write`, `wireless:config:read`. Save the integration and copy the **Client ID** and **Client Secret** (the secret is shown only once).
3. Set **Authentication Method** to **OAuth 2.0**, enter the **Client ID**, **Client Secret** and **Redirect URI**, and save the instance.
4. Run `!meraki-generate-login-url`, open the URL, sign in and approve access.
5. You are redirected to the Redirect URI (the page itself may not load). From the address bar, copy only the `code` value, which is the text between `code=` and `&state`. For example, from `https://localhost/?code=AbC123&state=xyz` copy `AbC123`. Paste it into **Authorization code** within 10 minutes and save the instance. Each code can be used only once.
6. Run `!meraki-auth-test`.

To authorize again, run `!meraki-auth-reset` and repeat steps 4–6.

#### API Key (all clusters)

1. Open your Meraki dashboard and go to **Organization** > **Settings**.
2. Make sure API access is set to **Enable access to the Cisco Meraki Dashboard API**.
3. Click your account email address (upper-right) > **My profile**, and generate an API key.
4. Set **Authentication Method** to **API Key**, enter the key in **API Key**, and click **Test**.
