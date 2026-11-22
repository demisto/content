## Get Your Slack User Token
This integration uses an Enterprise organization (or Business+) user token (starting with `xoxp-`).
In the Slack Enterprise connector this is the shared **User OAuth Token**, which also serves SaaS
posture, identity and data security and Slack audit log collection. It must hold the scopes of every
capability you enable, including the scopes in the SSPM onboarding documentation.

| Feature | Required scope | Who can create the token |
|---|---|---|
| User and group provisioning (SCIM `iam-*` commands) | `admin` | Org Owner (Enterprise) or Owner/Admin (Business+). The token can only act on accounts with the same or fewer permissions |
| `slack-user-session-reset` | `admin.users:write` | Enterprise organization Owner |
| Audit log collection (Slack Event Collector) | `auditlogs:read` | Enterprise organization Owner (admin tokens are not supported) |

The simplest way to acquire this token is for an Org Owner to create a Slack app, add the scopes above
as User Token Scopes, install the app on the organization, and use the generated user token.
The token-generating account must remain an Owner or Admin for SCIM updates to keep working.

For more information, see the [Slack SCIM documentation](https://api.slack.com/scim#accessing-the-scim-api) and
[admin.users.session.reset](https://api.slack.com/methods/admin.users.session.reset).

## Enable/Disable CRUD Commands
You can select which CRUD commands are enabled in the integration instance configuration settings. By default, all commands are enabled.

## Automatically create user if not found in update command
The *create-if-not-exists* parameter specifies if a new user should be created when the User Profile passed was not found in the 3rd-party integration.
