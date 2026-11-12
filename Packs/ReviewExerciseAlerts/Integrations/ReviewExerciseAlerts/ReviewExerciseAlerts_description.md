## Review Exercise Alerts

To configure the integration you need an OAuth client ID and client secret.

1. In the Review Exercise Alerts console, go to **Settings** > **API Clients**.
2. Create a new client with the **alerts:read** and **alerts:write** scopes.
3. Copy the client ID and client secret into the instance configuration.

Access tokens are cached in the integration context and refreshed automatically before they expire.
