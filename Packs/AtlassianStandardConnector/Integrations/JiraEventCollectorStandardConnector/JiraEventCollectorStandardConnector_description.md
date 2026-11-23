## Jira Event Collector (Standard Connector)

This integration is configured automatically as part of the Atlassian Standard Connector. Do not
configure it directly; set it up from the connector page. It collects the Jira audit log.

### Authentication

- **Jira Cloud, email + API token** (username / password profile): set the Server URL to your site
  (`https://<your-domain>.atlassian.net`); audit records are read from `/rest/api/3/auditing/record`.
- **Jira Data Center, username + password** (username / password profile) or **Personal Access Token**
  (API key profile, sent as `Authorization: Bearer`): set the Server URL to your Jira server; events are
  read from `/rest/auditing/1.0/events`.
- **Jira Cloud, OAuth 2.0 (3LO)**: the platform signs in and refreshes the token (the `jira-oauth-*`
  commands are not needed). The **Cloud ID** is required; requests go to
  `https://api.atlassian.com/ex/jira/<cloud_id>/rest/api/3/auditing/record`. Required scopes:
  `read:audit-log:jira`, `manage:jira-configuration`, `read:jira-work`, `read:jira-user`, `offline_access`.

The **Authentication method** parameter is ignored under the connector: the connection profile decides.
The user must be a Jira administrator (Data Center: `ADMIN`) to read the audit log.
