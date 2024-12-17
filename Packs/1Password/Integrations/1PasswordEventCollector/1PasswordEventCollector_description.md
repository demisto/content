## 1Password Event Collector Help

### How to Connect?

#### Server URL

The API server URL depends on the domain where the account is hosted.

| **Account Domain** | **API Server URL** |
| --- | --- |
| 1Password.com | https://events.1password.com (1Password Business)</br>https://events.ent.1password.com (1Password Enterprise)|
| 1Password.ca	| https://events.1password.ca |
| 1Password.eu	| https://events.1password.eu |

#### API Token

Every call to the 1Password Events API must be authorized with a bearer token. To issue a new bearer token:

1. Sign in to your 1Password account and click '**Integrations**' in the sidebar.
2. Choose the Events Reporting integration where you want to issue a token and click '**Add a token**'.
3. Enter a name for the bearer token and choose when it will expire.
4. Ensure the token includes features (scopes) consistent with event types to be fetched:

   | **Event Type** | **Token Feature** |
   | --- | --- |
   | Audit events | `auditevents` |
   | Item usage actions | `itemusages` |
   | Sign in attempts | `signinattempts` |

5. Click '**Issue Token**' to generate a new bearer token.
6. Store the token in a secure location (e.g. in a 1Password vault) and use it in configuring this instance in your XSIAM tenant.
