## Zscaler Internet Access via ZIdentity

This integration connects to the Zscaler Internet Access (ZIA) API using **OAuth 2.0 client credentials** authentication via ZIdentity, replacing the legacy session-based authentication.

---

## Prerequisites for OAuth 2.0 Authentication

* You must have an API subscription.
* You must have the [API Roles](https://help.zscaler.com/zia/adding-api-roles) configured in the ZIA Admin Portal.
* You must have your client applications registered on your authorization server with the required scope and configured appropriately.
* You must have your [OAuth 2.0 authorization server added](https://help.zscaler.com/zia/managing-oauth-2.0-authorization-servers#add-auth-server) to the ZIA Admin Portal.

## Setup Steps

1. Set up ZIdentity, link your service tenants, and create API Clients with the right roles and resources — [Getting Access](https://automate.zscaler.com/docs/getting-started/getting-started#getting-access).
2. Generate a **Client Secret** in ZIdentity when creating the API client.
3. Note your **Server URL** (e.g., `www.vanity.zslogin.net` if your login URL is `https://vanity.zslogin.net`).

## Instance Configuration

| Parameter | Description |
|-----------|-------------|
| **Server URL** | The Server URL assigned to your organization. For example, `www.vanity.zslogin.net`. |
| **Client ID** | The OAuth 2.0 client ID from ZIdentity. |
| **Client Secret** | The OAuth 2.0 client secret from ZIdentity. |
| **Auto Activate Changes** | If enabled, the integration will automatically activate configuration changes after each write command. If disabled, use the `zia-activate-changes` command manually. |
| **Suspicious URL categories** | Comma-separated list of URL categories to treat as suspicious. Default: `SUSPICIOUS_DESTINATION,SPYWARE_OR_ADWARE`. |
| **Source Reliability** | Reliability of the source providing the intelligence data. |

## Authentication Flow

The integration uses the OAuth 2.0 **client credentials** grant type:

1. Sends a POST request to `https://{server_url}/oauth2/v1/token` with `client_id`, `client_secret`, and `audience=https://api.zscaler.com`.
2. ZIdentity returns a Bearer access token.
3. All ZIA API calls use `Authorization: Bearer {access_token}`.

Access tokens are cached in the integration context and automatically refreshed when they expire.