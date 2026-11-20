# Keeper Security Event Collector

## Authentication

The integration uses a Keeper Admin REST API key. Creating a key requires Enterprise Root Administrator permissions.

1. Log in to the [Keeper Admin Console](https://keepersecurity.com/console/).
2. Go to **Integrations** > **API Keys** and create a new key with the **SIEM** (read) scope.
   Alternatively, in Keeper Commander run: `public-api-key generate --name "XSIAM" --integrations "SIEM:1" --expires 1y`
3. Copy the key (it is shown only once) and paste it in the **API Key** field of the instance configuration.

When the key expires or is revoked, events stop being collected, so choose the expiration accordingly.

## Server Regions

Use the URL of the region that hosts your account:

- US Instance: <https://keepersecurity.com>
- EU Instance: <https://keepersecurity.eu>
- AU Instance: <https://keepersecurity.com.au>
- GOV Instance: <https://govcloud.keepersecurity.us>
- CA Instance: <https://keepersecurity.ca>
- JP Instance: <https://keepersecurity.jp>

## Upgrading from the previous (Commander based) version

The previous version authenticated with a username and password and a device registration flow. That flow, and the
`keeper-security-register-*` commands, were removed. Replace the username and password with an API key as described above.
The event fields changed, see the release notes.