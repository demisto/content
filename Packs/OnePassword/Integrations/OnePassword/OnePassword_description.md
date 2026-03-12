## 1Password

### How to get the configuration parameters

#### Server URL

The API server URL depends on the region (domain) where the account is hosted and the pricing plan.

| **Domain** | **Plan** | **API Server URL** |
| --- | --- | --- |
| 1Password.com | Business | https://events.1password.com |
| 1Password.com | Enterprise | https://events.ent.1password.com |
| 1Password.ca | Any | https://events.1password.ca |
| 1Password.eu | Any | https://events.1password.eu |
| {sub}.{domain}.com | Any | https://events.{domain}.com |

#### API Token

Every call to the 1Password Events API must be authorized with a bearer token. To issue a new bearer token:

1. Sign in to your 1Password account and click **Integrations** in the sidebar.
2. Under the **Directory** tab, choose **(•••) Other** and enter a descriptive name for the integration, such as 'Cortex XSIAM'.
3. Enter a name for the bearer token and choose when it will expire.
4. Ensure the token has access to the event types:
   * Audit events (`auditevents` feature)
   * Item usage actions (`itemusages` feature)
   * Sign-in attempts (`signinattempts` feature)
5. Click **Issue Token** to generate a new bearer token.
6. Save the token in a secure location and use it in configuring this integration instance.

#### Maximum Number of Events per Fetch

It is recommended to configure the integration instance so that the maximum number of fetched events does not exceed **100,000 per minute per event type**. Otherwise, the 1Password Events API may raise rate limit errors (HTTP 429).
