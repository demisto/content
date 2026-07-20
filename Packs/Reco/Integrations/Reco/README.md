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
| Minimum risk level (e.g. MEDIUM fetches medium and higher) | The minimum severity threshold for fetched incidents. Accepts a single value: LOW, MEDIUM, HIGH, or CRITICAL (or numeric equivalents 10, 20, 30, 40). Alerts at or above this severity are fetched. | False |
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

***
Add a comment to an alert in Reco.

#### Base Command

`reco-add-comment-to-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to add the comment to. | Required |
| comment | Comment text. | Required |

### reco-update-incident-timeline

***
Add a comment to an incident timeline in Reco.

#### Base Command

`reco-update-incident-timeline`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required |
| comment | Comment text. | Required |

### reco-resolve-visibility-event

***
Resolve an event in a Reco Finding.

#### Base Command

`reco-resolve-visibility-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Entity ID of the file to resolve. | Required |
| label_name | Label name to resolve (e.g. `Accessible to All Org Users`). | Required |

### reco-get-risky-users

***
List all accounts flagged as risky (auto-paginates all results).

#### Base Command

`reco-get-risky-users`

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

***
Tag a user as risky in Reco.

#### Base Command

`reco-add-risky-user-label`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | Email address of the user to tag as risky. | Required |

### reco-add-leaving-org-user-label

***
Tag a user as a departing employee in Reco.

#### Base Command

`reco-add-leaving-org-user-label`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | Email address of the user to tag as departing. | Required |

### reco-get-assets-user-has-access-to

***
List files a user has access to.

#### Base Command

`reco-get-assets-user-has-access-to`

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

***
Find sensitive assets by name.

#### Base Command

`reco-get-sensitive-assets-by-name`

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

***
Find sensitive assets by ID.

#### Base Command

`reco-get-sensitive-assets-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID. | Required |

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

### reco-get-assets-by-id

***
Find any asset by ID.

#### Base Command

`reco-get-assets-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID. | Required |

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

### reco-get-link-to-user-overview-page

***
Generate a deep link to the Reco UI overview page for an entity.

#### Base Command

`reco-get-link-to-user-overview-page`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Entity type (e.g. `RM_LINK_TYPE_USER`). | Required |
| param | Entity ID or email. | Optional |

### reco-get-3rd-parties-accessible-to-data-list

***
List third-party domains that have access to sensitive data.

#### Base Command

`reco-get-3rd-parties-accessible-to-data-list`

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

***
List sensitive assets exposed via a public link.

#### Base Command

`reco-get-sensitive-assets-with-public-link`

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Assets.asset_id | String | Asset ID |
| Reco.Assets.asset | Unknown | Asset metadata |
| Reco.Assets.data_category | String | Primary data category |
| Reco.Assets.last_access_date | String | Last access date |

### reco-get-files-shared-with-3rd-parties

***
List files shared with a specific third-party domain.

#### Base Command

`reco-get-files-shared-with-3rd-parties`

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

***
Update the status of a Reco alert.

#### Base Command

`reco-change-alert-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required |
| status | New status. Possible values: `ALERT_STATUS_NEW`, `ALERT_STATUS_IN_PROGRESS`, `ALERT_STATUS_CLOSED`. | Required |

### reco-get-user-context-by-email-address

***
Get identity context for a user by email address.

#### Base Command

`reco-get-user-context-by-email-address`

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

***
List files accessible to a specific email address.

#### Base Command

`reco-get-files-exposed-to-email-address`

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

***
List files an owner has shared outside the organization.

#### Base Command

`reco-get-assets-shared-externally`

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

***
List private (non-corporate) email addresses with file access.

#### Base Command

`reco-get-private-email-list-with-access`

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.privateEmails.email_account | String | Private email account |
| Reco.privateEmails.primary_email | String | Associated corporate email |
| Reco.privateEmails.files_num | Number | Number of files accessible |
| Reco.privateEmails.user_category | String | User category |

### reco-get-alert-ai-summary

***
Get an AI-generated summary of an alert.

#### Base Command

`reco-get-alert-ai-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.AlertSummary.markdown | String | Markdown-formatted alert summary |

### reco-get-apps

***
List all discovered SaaS applications (auto-paginates all results).

#### Base Command

`reco-get-apps`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| before | Filter apps last seen before this date. | Optional |
| after | Filter apps last seen after this date. | Optional |
| limit | Page size (omit for all results). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Apps.id | String | The unique identifier of the application. |
| Reco.Apps.name | String | The name of the application. |
| Reco.Apps.category | String | The category of the application. |
| Reco.Apps.usersCount | Number | The number of users with access to the application. |
| Reco.Apps.authorization | String | The authorization/sanction status of the application. |
| Reco.Apps.authType | String | The authentication type used by the application. |
| Reco.Apps.isUsingAi | Boolean | Whether the application uses AI. |
| Reco.Apps.isShadowApp | Boolean | Whether the application is a shadow/unmanaged app. |
| Reco.Apps.vendorGrade | String | The vendor security grade of the application. |
| Reco.Apps.aiCapability | String | The AI capability description for the application. |
| Reco.Apps.lastSeen | Date | The last activity timestamp for the application. |

### reco-set-app-authorization-status

***
Update the authorization status of an application.

#### Base Command

`reco-set-app-authorization-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | Application ID. | Required |
| authorization_status | Authorization status. Possible values: `AUTH_STATUS_SANCTIONED`, `AUTH_STATUS_UNSANCTIONED`, `AUTH_STATUS_TO_REVIEW`, `AUTH_STATUS_ACCEPTED_RISK`, `AUTH_STATUS_EVALUATING`, `AUTH_STATUS_UNDER_INVESTIGATION`, `AUTH_STATUS_INVESTIGATED`, `AUTH_STATUS_CLOUD_INVENTORY`, `AUTH_STATUS_SYSTEM_SANCTIONED`. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.AppAuthorization.app_id | String | The application ID that was updated. |
| Reco.AppAuthorization.authorization_status | String | The authorization status that was set. |
| Reco.AppAuthorization.updated | Boolean | Whether the update was successful. |
| Reco.AppAuthorization.rows_affected | Number | Number of rows affected by the update operation. |

#### Command example

```
!reco-set-app-authorization-status app_id="microsoft.com" authorization_status="AUTH_STATUS_SANCTIONED"
```

### reco-add-exclusion-filter

***
Add values to a Reco classifier exclusion list.

#### Base Command

`reco-add-exclusion-filter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_to_add | Exclusion key (e.g. `CASE_SENSITIVE_TERMS`, `OWNERS`, `FILE_IDS`, `LOCATIONS`). | Required |
| values_to_add | Comma-separated values to add. | Required |

---

## List Commands (External API)

All commands below accept `filters` (SCIM v2 expression) and `limit` (default 1000).

### reco-list-events

***
List SaaS activity events.

#### Base Command

`reco-list-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "actor.email eq "user@example.com" and eventTime gt "2024-01-01T00:00:00Z""). | Optional |
| limit | The maximum number of events to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Events.id | String | Event ID |
| Reco.Events.eventType | String | Event type code |
| Reco.Events.formattedEventType | String | Human-readable event type |
| Reco.Events.application | String | Source SaaS application |
| Reco.Events.actorEmail | String | Actor email address |
| Reco.Events.actorName | String | Actor display name |
| Reco.Events.eventTime | Date | Event timestamp |
| Reco.Events.outcomeString | String | Event outcome description |

### reco-list-posture-issues

***
List security posture issues.

#### Base Command

`reco-list-posture-issues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "severity eq "HIGH""). | Optional |
| limit | The maximum number of posture issues to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.PostureIssues.id | String | Issue ID |
| Reco.PostureIssues.name | String | Issue name |
| Reco.PostureIssues.severity | String | Severity (LOW/MEDIUM/HIGH/CRITICAL) |
| Reco.PostureIssues.checkStatus | String | Check status |
| Reco.PostureIssues.scorePercentage | Number | Compliance score percentage |
| Reco.PostureIssues.checkedInstance | Unknown | The SaaS instance this issue was checked against |
| Reco.PostureIssues.url | String | Link to issue in Reco UI |

### reco-list-accounts

***
List SaaS accounts.

#### Base Command

`reco-list-accounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "isRiskyUser eq true" or "accountEmail co "@example.com""). | Optional |
| limit | The maximum number of accounts to return. Default is 1000. | Optional |

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

***
List managed and unmanaged devices.

#### Base Command

`reco-list-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "isUnmanaged eq true" or "devicePlatform eq "Windows""). | Optional |
| limit | The maximum number of devices to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Devices.id | String | Device ID |
| Reco.Devices.name | String | Device name |
| Reco.Devices.devicePlatform | String | Device platform (Windows, macOS, iOS, Android, etc.) |
| Reco.Devices.os | String | Operating system of the device |
| Reco.Devices.osVersion | String | Operating system version |
| Reco.Devices.isUnmanaged | Boolean | Whether the device is unmanaged (not enrolled in MDM) |
| Reco.Devices.hasNonCompliant | Boolean | Whether the device has non-compliant policies |
| Reco.Devices.lastSeen | Date | Last activity timestamp |

### reco-list-ai-agents

***
List detected AI agents.

#### Base Command

`reco-list-ai-agents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "authorization eq "AUTH_STATUS_UNSANCTIONED""). | Optional |
| limit | The maximum number of AI agents to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.AiAgents.id | String | AI agent ID |
| Reco.AiAgents.name | String | AI agent name |
| Reco.AiAgents.vendor | String | Vendor of the AI agent |
| Reco.AiAgents.type | String | Type of AI agent |
| Reco.AiAgents.authorization | String | Authorization/sanction status of the AI agent |
| Reco.AiAgents.agentStatus | String | Current status of the AI agent |
| Reco.AiAgents.risk | Number | Risk level of the AI agent (0=NA, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL) |
| Reco.AiAgents.lastUsage | Date | Last usage timestamp |

### reco-list-groups

***
List SaaS groups.

#### Base Command

`reco-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "name co "Engineering""). | Optional |
| limit | The maximum number of groups to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Groups.id | String | Group ID |
| Reco.Groups.name | String | Group name |
| Reco.Groups.email | String | Group email address |
| Reco.Groups.membersCount | Number | Number of members in the group |
| Reco.Groups.appsCount | Number | Number of apps the group has access to |

### reco-list-saas-to-saas

***
List SaaS-to-SaaS OAuth grants.

#### Base Command

`reco-list-saas-to-saas`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "authorization eq "AUTH_STATUS_UNSANCTIONED" or permissionRisk eq "30""). | Optional |
| limit | The maximum number of SaaS-to-SaaS grants to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.SaasToSaas.id | String | SaaS-to-SaaS grant ID |
| Reco.SaasToSaas.plugin | String | The plugin or app name receiving the grant |
| Reco.SaasToSaas.authorization | String | Authorization status of the grant |
| Reco.SaasToSaas.permissionRisk | String | Permission risk level (10=LOW, 20=MEDIUM, 30=HIGH) |
| Reco.SaasToSaas.accounts | Number | Number of accounts with this grant |
| Reco.SaasToSaas.aiCapability | String | AI capability of the third-party app |
| Reco.SaasToSaas.lastSeen | Date | Last activity timestamp for this grant |

### reco-list-ip-addresses

***
List observed IP addresses.

#### Base Command

`reco-list-ip-addresses`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "country eq "CN" or hasVpn eq true"). | Optional |
| limit | The maximum number of IP addresses to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.IpAddresses.ipAddress | String | The IP address or CIDR range |
| Reco.IpAddresses.country | String | Country of the IP address |
| Reco.IpAddresses.asnName | String | ASN name of the IP address |
| Reco.IpAddresses.eventsCount | Number | Number of events from this IP |
| Reco.IpAddresses.usersCount | Number | Number of users seen from this IP |
| Reco.IpAddresses.hasVpn | Boolean | Whether the IP is associated with a VPN |
| Reco.IpAddresses.hasProxy | Boolean | Whether the IP is associated with a proxy |
| Reco.IpAddresses.lastEventTime | Date | Last event timestamp from this IP |

### reco-list-business-units

***
List external business units.

#### Base Command

`reco-list-business-units`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "name eq "Finance""). | Optional |
| limit | The maximum number of business units to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.BusinessUnits.id | String | Business unit ID |
| Reco.BusinessUnits.name | String | Business unit name |
| Reco.BusinessUnits.manager | String | Manager of the business unit |
| Reco.BusinessUnits.createdAt | Date | Creation timestamp of the business unit |

### reco-list-audit-logs

***
List Reco platform audit logs.

#### Base Command

`reco-list-audit-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "userEmail eq "admin@example.com" and action eq "DELETE""). | Optional |
| limit | The maximum number of audit log entries to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.AuditLogs.id | String | Audit log entry ID |
| Reco.AuditLogs.userEmail | String | Email of the user who performed the action |
| Reco.AuditLogs.module | String | Module where the action was performed |
| Reco.AuditLogs.action | String | Action performed |
| Reco.AuditLogs.objectName | String | Name of the object affected |
| Reco.AuditLogs.timestamp | Date | Timestamp of the audit log entry |
| Reco.AuditLogs.remoteAddr | String | Remote IP address of the actor |

### reco-list-posture-checks

***
List posture check definitions.

#### Base Command

`reco-list-posture-checks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "severity eq "HIGH" and apps co "Google""). | Optional |
| limit | The maximum number of posture check definitions to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.PostureChecks.id | String | Posture check ID |
| Reco.PostureChecks.name | String | Posture check name |
| Reco.PostureChecks.severity | String | Severity of the posture check |
| Reco.PostureChecks.policyType | String | Policy type of the posture check |
| Reco.PostureChecks.apps | Unknown | Applications this posture check applies to |
| Reco.PostureChecks.type | String | Type of posture check (built-in or custom) |

### reco-list-threat-detection-policies

***
List threat detection policies.

#### Base Command

`reco-list-threat-detection-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "severity eq "HIGH" and status eq "ON""). | Optional |
| limit | The maximum number of policies to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.ThreatDetectionPolicies.id | String | Policy ID |
| Reco.ThreatDetectionPolicies.name | String | Policy name |
| Reco.ThreatDetectionPolicies.severity | String | Severity of the policy |
| Reco.ThreatDetectionPolicies.status | String | Status of the policy (ON, OFF, or PREVIEW) |
| Reco.ThreatDetectionPolicies.apps | Unknown | Applications monitored by the policy |
| Reco.ThreatDetectionPolicies.openAlerts | Number | Number of open alerts triggered by this policy |
| Reco.ThreatDetectionPolicies.type | String | Type of policy (built-in or custom) |

### reco-list-exclusions

***
List alert suppression exclusion rules.

#### Base Command

`reco-list-exclusions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "policyName co "MFA""). | Optional |
| limit | The maximum number of exclusions to return. Default is 1000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Exclusions.id | String | Exclusion rule ID |
| Reco.Exclusions.name | String | Exclusion rule name |
| Reco.Exclusions.policyName | String | Name of the policy this exclusion applies to |
| Reco.Exclusions.apps | Unknown | Applications this exclusion applies to |
| Reco.Exclusions.createdBy | String | User who created the exclusion |
| Reco.Exclusions.createdAt | Date | Creation timestamp of the exclusion |

### reco-list-app-instances

***
List integrated app instances (app portfolio). Only returns instances with an active integration status.

#### Base Command

`reco-list-app-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | The SCIM v2 filter expression (e.g. "isUsingAi eq true"). | Optional |
| limit | The maximum number of app instances to return. Default is 1000. | Optional |

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
