## Cisco Meraki Event Collector

Collects configuration changes, network events, API requests and appliance security events from the Meraki Dashboard API.

### Base URL

| Region | Base URL |
| --- | --- |
| Global (North America, South America, Europe, Asia-Pacific) | https://api.meraki.com |
| Canada | https://api.meraki.ca |
| China | https://api.meraki.cn |
| India | https://api.meraki.in |
| United States FedRAMP | https://api.gov-meraki.com |

### Authentication

Configure **either** OAuth 2.0 **or** an API key. OAuth 2.0 is supported only for https://api.meraki.com.

#### OAuth 2.0

1. In the Meraki Dashboard, register an OAuth integration and set its redirect URI.
2. Grant the scopes `dashboard:general:config:read`, `dashboard:general:telemetry:read` and `sdwan:telemetry:read`.
3. Enter the **Client ID**, **Client Secret** and **Redirect URI** and save the instance.
4. Run `!cisco-meraki-generate-login-url`, sign in, and copy the `code` value from the redirect URL.
5. Enter it in **Authorization code**, save the instance, and run `!cisco-meraki-auth-test`.

#### API key

Generate an API key in the Meraki Dashboard under **My Profile** > **API access** and enter it in **API Key**.

### Organization ID

Find it at the bottom of any Meraki Dashboard page, or with `GET /organizations`.

### Network events

Network events are collected per network and product type. Leave **Network IDs** empty to collect from all the networks of the organization; the network list is refreshed every 24 hours.
