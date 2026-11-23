## Atlassian Jira v3 (Standard Connector)

This integration is configured automatically as part of the Atlassian Standard Connector. Do not
configure it directly; set it up from the connector page.

### Authentication

- **Jira Cloud, email + API token** (username / password profile): your Atlassian account email and
  an [API token](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/).
- **Jira Data Center, username + password** (username / password profile).
- **Jira Data Center, Personal Access Token** (API key profile): sent as `Authorization: Bearer`.
- **Jira Cloud, OAuth 2.0 (3LO)**: the platform signs in and refreshes the token, so the
  `jira-oauth-start` / `jira-oauth-complete` commands are not needed. Required scopes:
  `read:jira-work`, `read:jira-user`, `write:jira-work`, `read:jql:jira`, `read:issue-details:jira`,
  `read:board-scope:jira-software`, `write:board-scope:jira-software`, `read:sprint:jira-software`,
  `write:sprint:jira-software`, `read:epic:jira-software`, `offline_access`.

For Jira Cloud set the **Cloud ID** (shown in `https://admin.atlassian.com/s/{cloud_id}/users`) and keep the
default Server URL `https://api.atlassian.com/ex/jira`. For Jira Data Center leave the Cloud ID empty and set
the Server URL to your Jira server.

The user needs the project permissions: Browse projects, Create / Edit / Delete / Transition issues,
Create attachments, Add comments and Link issues.
