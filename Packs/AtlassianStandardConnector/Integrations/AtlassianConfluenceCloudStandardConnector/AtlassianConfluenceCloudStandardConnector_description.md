## Atlassian Confluence Cloud (Standard Connector)

This integration is configured automatically as part of the Atlassian Standard Connector. Do not
configure it directly; set it up from the connector page.

### Authentication

- **Email + API token** (username / password connection profile): the Atlassian account email
  and an API token created at https://id.atlassian.com/manage/api-tokens. Requests are sent with
  Basic authentication to the site URL (`https://<site>.atlassian.net`), so the **Site Name** is
  required.
- **OAuth 2.0 (3LO)** (authorization code connection profile): the platform signs in and refreshes
  the token, so `!confluence-cloud-oauth-start` and `!confluence-cloud-oauth-complete` are not
  needed. Requests go through the Atlassian API gateway
  (`https://api.atlassian.com/ex/confluence/<cloud_id>`), so the **Cloud ID** is required (find it
  at `https://<site>.atlassian.net/_edge/tenant_info`). The OAuth app needs the granular scopes
  `read:audit-log:confluence` (event collection), `read/write/delete:content:confluence`,
  `read:content-details:confluence`, `read/write/delete:page:confluence`,
  `read/write/delete:blogpost:confluence`, `read/write/delete:custom-content:confluence`,
  `read/write:comment:confluence`, `write:template:confluence`,
  `read/write/delete:space:confluence`, `read:space-details:confluence`,
  `read:group:confluence` and `offline_access`.

Event collection reads the audit log, which requires a Confluence administrator account.
