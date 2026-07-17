Reco is the leader in SaaS & AI Security — securing AI sprawl across SaaS apps and agents. This integration connects Reco's SaaS & AI Security platform to Cortex XSOAR, enabling real-time threat response, posture management, AI governance, and identity risk workflows.

This integration was integrated and tested with Reco External API v1.

## Configure Reco in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://host.reco.ai/api/v1) | Base URL of your Reco instance | True |
| JWT app token | API Token (Bearer) | True |
| Trust any certificate (not secure) | Skip TLS verification | False |
| Use system proxy settings | Route requests through the system proxy | False |
| Incident type | Incident type to map Reco alerts to | False |
| Fetch incidents | Enable automatic incident fetching | False |
| Max fetch | Maximum incidents to fetch per run (up to 500) | False |
| Source | Filter fetched incidents by SaaS source | False |
| Before | Fetch incidents created before this timestamp | False |
| After | Fetch incidents created after this timestamp | False |
| Risk level | Severity filter for fetched incidents. Accepts a single value or comma-separated list. Values: LOW, MEDIUM, HIGH, CRITICAL (or numeric 10/20/30/40). Example: `HIGH,CRITICAL` | False |
| First fetch timestamp | How far back to fetch on first run (e.g. `7 days`, `12 hours`) | False |

## SCIM v2 Filters

All `reco-list-*` commands accept an optional `filters` argument using SCIM v2 syntax:

| Operator | Meaning | Example |
| --- | --- | --- |
| `eq` | Equals | `severity eq "HIGH"` |
| `ne` | Not equals | `status ne "CLOSED"` |
| `co` | Contains | `email co "@example.com"` |
| `sw` | Starts with | `name sw "John"` |
| `gt` / `ge` | Greater than / or equal | `createdAt gt "2024-01-01T00:00:00Z"` |
| `lt` / `le` | Less than / or equal | `lastSeen le "2024-12-31T23:59:59Z"` |
| `in` | Matches any listed value | `severity in ["HIGH","CRITICAL"]` |
| `not in` | Excludes listed values | `status not in ["CLOSED"]` |
| `and` / `or` / `not` | Logical operators | `isAdmin eq true and hasMfa eq false` |

Pagination is embedded in the filter string: `limit eq 100 and page eq 1`.

## Commands

### reco-add-comment-to-alert

Add a comment to an alert in Reco.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to add the comment to. | Required |
| comment | Comment text. | Required |

### reco-update-incident-timeline

Add a comment to an incident timeline in Reco.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required |
| comment | Comment text. | Required |

### reco-resolve-visibility-event

Resolve an event in a Reco Finding.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Entity ID of the file to resolve. | Required |
| label_name | Label name to resolve (e.g. `Accessible to All Org Users`). | Required |

### reco-get-risky-users

List all accounts flagged as risky (auto-paginates all results).

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.RiskyUsers.id | String | Account ID |
| Reco.RiskyUsers.name | String | Account display name |
| Reco.RiskyUsers.accountEmail | String | Account email address |
| Reco.RiskyUsers.permissions | String | Account permissions (ADMIN / PRIVILEGED / STANDARD) |
| Reco.RiskyUsers.hasMfa | String | MFA status (MFA / NOMFA / NA) |
| Reco.RiskyUsers.openAlerts | Number | Number of open alerts for this account |
| Reco.RiskyUsers.isAdmin | Boolean | Whether the account has admin privileges |
| Reco.RiskyUsers.isRiskyUser | Boolean | Whether the account is flagged as risky |
| Reco.RiskyUsers.lastSeen | Date | Last activity timestamp |

### reco-add-risky-user-label

Tag a user as risky in Reco.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | Email address of the user to tag as risky. | Required |

### reco-add-leaving-org-user-label

Tag a user as a departing employee in Reco.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | Email address of the user to tag as departing. | Required |

### reco-get-assets-user-has-access-to

List files a user has access to.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | User email address. | Required |
| only_sensitive | Return only sensitive assets. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Assets | Unknown | Assets the user has access to |

### reco-get-sensitive-assets-by-name

Find sensitive assets by name.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_name | Asset name to search for. | Required |
| regex_search | Use substring/contains matching instead of exact match. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.SensitiveAssets.id | String | Asset ID |
| Reco.SensitiveAssets.name | String | Asset name |
| Reco.SensitiveAssets.owner | String | Asset owner |
| Reco.SensitiveAssets.url | String | Asset URL |
| Reco.SensitiveAssets.sensitivityLevel | Number | Sensitivity level (30=HIGH, 40=CRITICAL) |
| Reco.SensitiveAssets.permissionVisibility | String | Permission visibility (PUBLIC / INTERNAL / RESTRICTED) |
| Reco.SensitiveAssets.location | String | File path |
| Reco.SensitiveAssets.dataCategories | Unknown | Detected data categories |

### reco-get-sensitive-assets-by-id

Find sensitive assets by ID.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID. | Required |

#### Context Output

Same as `reco-get-sensitive-assets-by-name`.

### reco-get-assets-by-id

Find any asset by ID.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID. | Required |

#### Context Output

Same as `reco-get-sensitive-assets-by-name`.

### reco-get-link-to-user-overview-page

Generate a deep link to the Reco UI overview page for an entity.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Entity type (e.g. `RM_LINK_TYPE_USER`). | Required |
| param | Entity ID or email. | Optional |

### reco-get-3rd-parties-accessible-to-data-list

List third-party domains that have access to sensitive data.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_interaction_time_in_days | Include domains with activity within this many days. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Domains.domain | String | Third-party domain |
| Reco.Domains.last_activity | String | Last interaction date |
| Reco.Domains.files_num | Number | Number of files accessible |
| Reco.Domains.users_with_access_num | Number | Number of users with access |

### reco-get-sensitive-assets-with-public-link

List sensitive assets exposed via a public link.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Assets.asset_id | String | Asset ID |
| Reco.Assets.asset | Unknown | Asset metadata |
| Reco.Assets.data_category | String | Primary data category |
| Reco.Assets.last_access_date | String | Last access date |

### reco-get-files-shared-with-3rd-parties

List files shared with a specific third-party domain.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Third-party domain to query. | Required |
| last_interaction_time_in_days | Include files with activity within this many days. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Assets.asset_id | String | Asset ID |
| Reco.Assets.location | String | File location |
| Reco.Assets.file_owner | String | File owner |
| Reco.Assets.domain | String | Third-party domain |
| Reco.Assets.last_access_date | String | Last access date |

### reco-change-alert-status

Update the status of a Reco alert.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required |
| status | New status. Possible values: `ALERT_STATUS_NEW`, `ALERT_STATUS_IN_PROGRESS`, `ALERT_STATUS_CLOSED`. | Required |

### reco-get-user-context-by-email-address

Get identity context for a user by email address.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | User email address. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.User.id | String | Identity ID |
| Reco.User.email | String | Primary email address |
| Reco.User.name | String | Full name |
| Reco.User.departments | String | Departments |
| Reco.User.jobTitles | String | Job titles |
| Reco.User.isFormer | Boolean | Whether the user is a former employee |
| Reco.User.isInternal | Boolean | Whether the user is an internal employee |
| Reco.User.openAlerts | Number | Number of open alerts |
| Reco.User.lastSeen | Date | Last activity timestamp |

### reco-get-files-exposed-to-email-address

List files accessible to a specific email address.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | Email address. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Assets.asset_id | String | Asset ID |
| Reco.Assets.location | String | File location |
| Reco.Assets.email_account | String | Email account with access |
| Reco.Assets.file_owner | String | File owner |

### reco-get-assets-shared-externally

List files an owner has shared outside the organization.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | File owner email address. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Assets.asset_id | String | Asset ID |
| Reco.Assets.file_owner | String | File owner |
| Reco.Assets.last_access_date | String | Last access date |

### reco-get-private-email-list-with-access

List private (non-corporate) email addresses with file access.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.privateEmails.email_account | String | Private email account |
| Reco.privateEmails.primary_email | String | Associated corporate email |
| Reco.privateEmails.files_num | Number | Number of files accessible |
| Reco.privateEmails.user_category | String | User category |

### reco-get-alert-ai-summary

Get an AI-generated summary of an alert.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.AlertSummary.markdown | String | Markdown-formatted alert summary |

### reco-get-apps

List all discovered SaaS applications (auto-paginates all results).

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| before | Filter apps last seen before this date. | Optional |
| after | Filter apps last seen after this date. | Optional |
| limit | Page size (omit for all results). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Apps.id | String | App ID |
| Reco.Apps.name | String | App name |
| Reco.Apps.category | String | App category |
| Reco.Apps.usersCount | Number | Number of users |
| Reco.Apps.authorization | String | Authorization status |
| Reco.Apps.isUsingAi | Boolean | Whether the app uses AI |
| Reco.Apps.isShadowApp | Boolean | Whether the app is unsanctioned shadow IT |
| Reco.Apps.vendorGrade | String | Vendor security grade (A–F) |
| Reco.Apps.aiCapability | String | AI capability (AI-Native / AI-Assisted / No-AI) |
| Reco.Apps.lastSeen | Date | Last activity timestamp |

### reco-set-app-authorization-status

Update the authorization status of an application.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | Application ID. | Required |
| authorization_status | Authorization status. Possible values: `AUTH_STATUS_SANCTIONED`, `AUTH_STATUS_UNSANCTIONED`, `AUTH_STATUS_TO_REVIEW`, `AUTH_STATUS_ACCEPTED_RISK`, `AUTH_STATUS_EVALUATING`, `AUTH_STATUS_UNDER_INVESTIGATION`, `AUTH_STATUS_INVESTIGATED`, `AUTH_STATUS_CLOUD_INVENTORY`, `AUTH_STATUS_SYSTEM_SANCTIONED`. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.AppAuthorization.app_id | String | Application ID |
| Reco.AppAuthorization.authorization_status | String | New authorization status |
| Reco.AppAuthorization.updated | Boolean | Whether the update succeeded |

#### Command example

```
!reco-set-app-authorization-status app_id="microsoft.com" authorization_status="AUTH_STATUS_SANCTIONED"
```

### reco-add-exclusion-filter

Add values to a Reco classifier exclusion list.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_to_add | Exclusion key (e.g. `CASE_SENSITIVE_TERMS`, `OWNERS`, `FILE_IDS`, `LOCATIONS`). | Required |
| values_to_add | Comma-separated values to add. | Required |

---

## List Commands (External API)

All commands below accept `filters` (SCIM v2 expression) and `limit` (default 1000).

### reco-list-events

List SaaS activity events.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Events.id | String | Event ID |
| Reco.Events.eventType | String | Event type code |
| Reco.Events.formattedEventType | String | Human-readable event type |
| Reco.Events.application | String | Source SaaS application |
| Reco.Events.actorEmail | String | Actor email address |
| Reco.Events.eventTime | Date | Event timestamp |
| Reco.Events.outcomeString | String | Event outcome description |

### reco-list-posture-issues

List security posture issues.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.PostureIssues.id | String | Issue ID |
| Reco.PostureIssues.name | String | Issue name |
| Reco.PostureIssues.severity | String | Severity (LOW/MEDIUM/HIGH/CRITICAL) |
| Reco.PostureIssues.checkStatus | String | Check status |
| Reco.PostureIssues.scorePercentage | Number | Compliance score percentage |
| Reco.PostureIssues.url | String | Link to issue in Reco UI |

### reco-list-accounts

List SaaS accounts.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Accounts.id | String | Account ID |
| Reco.Accounts.name | String | Account display name |
| Reco.Accounts.accountEmail | String | Account email address |
| Reco.Accounts.permissions | String | Permission level |
| Reco.Accounts.hasMfa | String | MFA status |
| Reco.Accounts.openAlerts | Number | Open alerts count |
| Reco.Accounts.isAdmin | Boolean | Admin flag |
| Reco.Accounts.isRiskyUser | Boolean | Risky user flag |
| Reco.Accounts.lastSeen | Date | Last activity |

### reco-list-devices

List managed and unmanaged devices.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Devices.id | String | Device ID |
| Reco.Devices.name | String | Device name |
| Reco.Devices.devicePlatform | String | Platform (Windows / macOS / iOS / Android) |
| Reco.Devices.isUnmanaged | Boolean | Whether the device is unmanaged |
| Reco.Devices.hasNonCompliant | Boolean | Whether the device has policy violations |
| Reco.Devices.lastSeen | Date | Last activity |

### reco-list-ai-agents

List detected AI agents.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.AiAgents.id | String | AI agent ID |
| Reco.AiAgents.name | String | Agent name |
| Reco.AiAgents.vendor | String | Vendor |
| Reco.AiAgents.authorization | String | Authorization status |
| Reco.AiAgents.risk | String | Risk level |
| Reco.AiAgents.lastUsage | Date | Last usage |

### reco-list-groups

List SaaS groups.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Groups.id | String | Group ID |
| Reco.Groups.name | String | Group name |
| Reco.Groups.email | String | Group email |
| Reco.Groups.membersCount | Number | Member count |

### reco-list-saas-to-saas

List SaaS-to-SaaS OAuth grants.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.SaasToSaas.id | String | Grant ID |
| Reco.SaasToSaas.plugin | String | Plugin / app name |
| Reco.SaasToSaas.authorization | String | Authorization status |
| Reco.SaasToSaas.permissionRisk | String | Permission risk level |
| Reco.SaasToSaas.aiCapability | String | AI capability |

### reco-list-ip-addresses

List observed IP addresses.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.IpAddresses.ipAddress | String | IP address |
| Reco.IpAddresses.country | String | Country |
| Reco.IpAddresses.eventsCount | Number | Event count |
| Reco.IpAddresses.hasVpn | Boolean | VPN flag |
| Reco.IpAddresses.hasProxy | Boolean | Proxy flag |

### reco-list-business-units

List external business units.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.BusinessUnits.id | String | Business unit ID |
| Reco.BusinessUnits.name | String | Business unit name |
| Reco.BusinessUnits.manager | String | Manager |

### reco-list-audit-logs

List Reco platform audit logs.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.AuditLogs.id | String | Log entry ID |
| Reco.AuditLogs.userEmail | String | Actor email |
| Reco.AuditLogs.module | String | Module |
| Reco.AuditLogs.action | String | Action performed |
| Reco.AuditLogs.timestamp | Date | Timestamp |

### reco-list-posture-checks

List posture check definitions.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.PostureChecks.id | String | Check ID |
| Reco.PostureChecks.name | String | Check name |
| Reco.PostureChecks.severity | String | Severity |
| Reco.PostureChecks.apps | Unknown | Applicable apps |

### reco-list-threat-detection-policies

List threat detection policies.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.ThreatDetectionPolicies.id | String | Policy ID |
| Reco.ThreatDetectionPolicies.name | String | Policy name |
| Reco.ThreatDetectionPolicies.severity | String | Severity |
| Reco.ThreatDetectionPolicies.status | String | ON / OFF / PREVIEW |
| Reco.ThreatDetectionPolicies.openAlerts | Number | Open alerts |

### reco-list-exclusions

List alert suppression exclusion rules.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Exclusions.id | String | Exclusion ID |
| Reco.Exclusions.name | String | Exclusion name |
| Reco.Exclusions.policyName | String | Associated policy |
| Reco.Exclusions.createdBy | String | Created by |

### reco-list-app-instances

List integrated app instances (app portfolio). Only returns instances with an active integration status.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.AppInstances.id | String | App instance ID |
| Reco.AppInstances.name | String | App instance name |
| Reco.AppInstances.instanceType | String | Instance type |
| Reco.AppInstances.accountsCount | Number | Number of accounts |
| Reco.AppInstances.isUsingAi | Boolean | Whether AI features are used |
| Reco.AppInstances.saasToSaasCount | Number | SaaS-to-SaaS grant count |
| Reco.AppInstances.filesCount | Number | File count |
