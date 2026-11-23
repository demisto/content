## Atlassian Confluence Server (Standard Connector)

This integration is configured automatically as part of the Atlassian Standard Connector. Do not
configure it directly; set it up from the connector page.

### Authentication

- **Username and password** (username / password connection profile): a Confluence Server / Data
  Center account, sent with Basic authentication on every request.
- **Personal Access Token** (API key connection profile): a token created in Confluence under
  **Profile > Settings > Personal Access Tokens** (Confluence 7.9 or later), sent as an
  `Authorization: Bearer <token>` header.

Set the **Server URL** (for example `https://confluence.example.com`) on the connector page. The
account (or the token owner) needs permission to view, create, update and delete content in the
spaces the integration works with, and the **Create Space** global permission for
`confluence-create-space`.
