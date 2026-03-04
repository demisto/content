Use the Jira Event Collector integration to get Audit logs using REST APIs.

Before you start, you need to get your-domain, username, and password. For more information, see [Jira Documentation](https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/#ad-hoc-api-calls).

## Configuration Parameters

**Server URL**
The endpoint to get the logs. For example, ``https://{{your-domain}}.atlassian.net``

**User name and Password**
The user name and password.

## Authentication Methods

### Basic Authentication
Provide your email address and API token generated from your Jira account settings.

### OAuth 2.0 Authentication

#### Required Scopes for Jira Cloud

The following OAuth 2.0 scopes must be configured in the [Atlassian Developer Console](https://developer.atlassian.com/console/myapps/) for your OAuth app to fetch audit events:

- `read:audit-log:jira` — Granular scope for reading Jira audit log records (required for event fetching)
- `manage:jira-configuration` — Classic admin scope required by the audit API
- `read:jira-work` — Required for Jira API v3 access
- `read:jira-user` — User information access
- `offline_access` — Enables refresh token for unattended access

#### Required Scopes for Jira On-Prem/Data Center

- `ADMIN` — Admin-level scope required for audit log access on Data Center instances
