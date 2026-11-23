### Authentication

In the Atlassian Standard Connector this integration authenticates with an **API key**
connection profile: a Jira Service Management (Assets) personal access token. The token
is sent on every request as `Authorization: Bearer <token>`.

To create the token, follow [Using personal access tokens](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html).

### Required permissions

- The owner of the token must be at least an **Asset Developer**.
- The user must have a premium license to Jira Service Management.

### Server URL

The integration appends `/rest/assets/1.0/` to the configured Server URL.

### Version support

This integration currently supports only on-prem clients with JSM version 5.4.15.
