# Datadog Cloud SIEM V2

Datadog Cloud SIEM V2 integration for Cortex XSOAR provides security signal management and log search capabilities for threat detection and incident response.

This integration allows security teams to:

-   Fetch security signals as XSOAR incidents automatically
-   Retrieve and filter security signals from Datadog's Cloud SIEM platform
-   Manage signal triage states and assignments
-   Search security logs for investigations
-   Extract IOCs (IPs, URLs, file hashes) from security signals

This integration was integrated and tested with version 2.12.0 of datadog-api-client.

## Configure Datadog Cloud SIEM V2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Instances**.
2. Search for Datadog Cloud SIEM V2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**    | **Description**                                                                 | **Required** |
    | ---------------- | ------------------------------------------------------------------------------- | ------------ |
    | Server URL       | Datadog website URL (e.g. datadoghq.com)                                        | True         |
    | API Key          | The API Key to use for authentication                                           | True         |
    | APP Key          | The APP Key to use for authentication                                           | True         |
    | Fetch incidents  | Enable fetching security signals as incidents                                   | False        |
    | Incident type    | The incident type to assign to fetched incidents                                | False        |
    | First fetch time | Time range for initial fetch (e.g., "3 days", "7 days")                         | False        |
    | Max fetch        | Maximum number of incidents to fetch per cycle                                  | False        |
    | Fetch severity   | Comma-separated list of severities to fetch (info, low, medium, high, critical) | False        |
    | Fetch state      | Signal state to fetch (open, under_review, archived)                            | False        |
    | Fetch query      | Additional custom query filter using Datadog search syntax                      | False        |

4. Click **Test** to validate the URLs, keys, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### datadog-signal-get

---

Get a specific security signal by ID from Datadog Cloud SIEM V2.

#### Base Command

`datadog-signal-get`

#### Input

| **Argument Name** | **Description**                                                                                                              | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------ |
| signal_id         | The unique identifier of the security signal to retrieve. If not provided, will attempt to get it from the current incident. | Optional     |

#### Context Output

| **Path**                                      | **Type** | **Description**                                                                   |
| --------------------------------------------- | -------- | --------------------------------------------------------------------------------- |
| Datadog.SecuritySignal.id                     | String   | The unique identifier of the security signal.                                     |
| Datadog.SecuritySignal.event_id               | String   | The event ID of the security signal.                                              |
| Datadog.SecuritySignal.timestamp              | String   | The timestamp when the security signal was generated.                             |
| Datadog.SecuritySignal.host                   | String   | Host associated with the security signal.                                         |
| Datadog.SecuritySignal.service                | String   | Services associated with the security signal.                                     |
| Datadog.SecuritySignal.severity               | String   | The severity level of the security signal \(info, low, medium, high, critical\).  |
| Datadog.SecuritySignal.title                  | String   | The title of the security signal.                                                 |
| Datadog.SecuritySignal.message                | String   | The message describing the security signal.                                       |
| Datadog.SecuritySignal.tags                   | Unknown  | List of tags associated with the security signal.                                 |
| Datadog.SecuritySignal.triggering_log_id      | String   | ID of the log that triggered the security signal.                                 |
| Datadog.SecuritySignal.url                    | String   | URL to view the security signal in Datadog UI.                                    |
| Datadog.SecuritySignal.rule.id                | String   | The unique identifier of the security rule.                                       |
| Datadog.SecuritySignal.rule.url               | String   | URL to view the security rule in Datadog UI.                                      |
| Datadog.SecuritySignal.triage.state           | String   | The current triage state of the security signal \(open, under_review, archived\). |
| Datadog.SecuritySignal.triage.archive_comment | String   | The archive comment of the security signal.                                       |
| Datadog.SecuritySignal.triage.archive_reason  | String   | The archive reason of the security signal.                                        |
| Datadog.SecuritySignal.triage.assignee.name   | String   | The name of the user assigned to the security signal.                             |
| Datadog.SecuritySignal.triage.assignee.handle | String   | The handle of the user assigned to the security signal.                           |
| Datadog.SecuritySignal.raw                    | Unknown  | The raw signal object returned by the API.                                        |

#### Command example

`!datadog-signal-get signal_id=AZm-wsEuAACEnzdcj-YEigAA`

`!datadog-signal-get`

---

### datadog-signal-list

---

Get a list of security signals from Datadog Cloud SIEM V2 with optional filtering and pagination.

#### Base Command

`datadog-signal-list`

#### Input

| **Argument Name** | **Description**                                                                                                                         | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| state             | Filter signals by state. Possible values are: open, under_review, archived.                                                             | Optional     |
| severity          | Filter signals by severity level. Possible values are: info, low, medium, high, critical.                                               | Optional     |
| source            | Filter signals by source.                                                                                                               | Optional     |
| query             | Custom query string for advanced filtering. Uses Datadog search syntax.                                                                 | Optional     |
| from_date         | Start date for the search. Format can be relative \(e.g., "7 days ago"\) or absolute \(e.g., "2023-01-01T00:00:00Z"\). Default: -7days. | Optional     |
| to_date           | End date for the search. Format can be relative \(e.g., "now"\) or absolute \(e.g., "2023-01-01T23:59:59Z"\). Default: now.             | Optional     |
| sort              | Sort order for results. Possible values are: asc, desc. Default: desc.                                                                  | Optional     |
| page_size         | Number of results per page.                                                                                                             | Optional     |
| limit             | Maximum number of results to return. If page_size is specified, limit is ignored. Default: 50.                                          | Optional     |

#### Context Output

| **Path**                                      | **Type** | **Description**                                                                   |
| --------------------------------------------- | -------- | --------------------------------------------------------------------------------- |
| Datadog.SecuritySignal.id                     | String   | The unique identifier of the security signal.                                     |
| Datadog.SecuritySignal.event_id               | String   | The event ID of the security signal.                                              |
| Datadog.SecuritySignal.timestamp              | String   | The timestamp when the security signal was generated.                             |
| Datadog.SecuritySignal.host                   | String   | Host associated with the security signal.                                         |
| Datadog.SecuritySignal.service                | String   | Services associated with the security signal.                                     |
| Datadog.SecuritySignal.severity               | String   | The severity level of the security signal \(info, low, medium, high, critical\).  |
| Datadog.SecuritySignal.title                  | String   | The title of the security signal.                                                 |
| Datadog.SecuritySignal.message                | String   | The message describing the security signal.                                       |
| Datadog.SecuritySignal.tags                   | Unknown  | List of tags associated with the security signal.                                 |
| Datadog.SecuritySignal.triggering_log_id      | String   | ID of the log that triggered the security signal.                                 |
| Datadog.SecuritySignal.url                    | String   | URL to view the security signal in Datadog UI.                                    |
| Datadog.SecuritySignal.rule.id                | String   | The unique identifier of the security rule.                                       |
| Datadog.SecuritySignal.rule.url               | String   | URL to view the security rule in Datadog UI.                                      |
| Datadog.SecuritySignal.triage.state           | String   | The current triage state of the security signal \(open, under_review, archived\). |
| Datadog.SecuritySignal.triage.archive_comment | String   | The archive comment of the security signal.                                       |
| Datadog.SecuritySignal.triage.archive_reason  | String   | The archive reason of the security signal.                                        |
| Datadog.SecuritySignal.triage.assignee.name   | String   | The name of the user assigned to the security signal.                             |
| Datadog.SecuritySignal.triage.assignee.handle | String   | The handle of the user assigned to the security signal.                           |
| Datadog.SecuritySignal.raw                    | Unknown  | The raw signal object returned by the API.                                        |

#### Command example

`!datadog-signal-list state=open severity=high`

`!datadog-signal-list from_date="-3days" to_date="now" limit=10`

---

### datadog-signal-update

---

Update a security signal's assignee and/or state in Datadog Cloud SIEM V2. Can update assignee only, state only, or both in a single command.

#### Base Command

`datadog-signal-update`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                      | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------ |
| signal_id         | The unique identifier of the security signal to update. If not provided, will attempt to get it from the current incident.                                                                                                           | Optional     |
| assignee          | Name or email of the user to assign to the security signal. Leave empty to unassign. At least one of assignee or state must be provided.                                                                                             | Optional     |
| state             | The new state of the security signal. Possible values are: open, under_review, archived. At least one of assignee or state must be provided.                                                                                         | Optional     |
| archive_reason    | Reason for the state change \(used when changing state to archived\). Possible values are: none, false_positive, testing_or_maintenance, remediated, investigated_case_opened, other, true_positive_benign, true_positive_malicious. | Optional     |
| archive_comment   | Comment about the state change \(used when changing state to archived\).                                                                                                                                                             | Optional     |

#### Context Output

| **Path**                                      | **Type** | **Description**                                                                   |
| --------------------------------------------- | -------- | --------------------------------------------------------------------------------- |
| Datadog.SecuritySignal.id                     | String   | The unique identifier of the security signal.                                     |
| Datadog.SecuritySignal.event_id               | String   | The event ID of the security signal.                                              |
| Datadog.SecuritySignal.timestamp              | String   | The timestamp when the security signal was generated.                             |
| Datadog.SecuritySignal.host                   | String   | Host associated with the security signal.                                         |
| Datadog.SecuritySignal.service                | String   | Services associated with the security signal.                                     |
| Datadog.SecuritySignal.severity               | String   | The severity level of the security signal \(info, low, medium, high, critical\).  |
| Datadog.SecuritySignal.title                  | String   | The title of the security signal.                                                 |
| Datadog.SecuritySignal.message                | String   | The message describing the security signal.                                       |
| Datadog.SecuritySignal.tags                   | Unknown  | List of tags associated with the security signal.                                 |
| Datadog.SecuritySignal.triggering_log_id      | String   | ID of the log that triggered the security signal.                                 |
| Datadog.SecuritySignal.url                    | String   | URL to view the security signal in Datadog UI.                                    |
| Datadog.SecuritySignal.rule.id                | String   | The unique identifier of the security rule.                                       |
| Datadog.SecuritySignal.rule.url               | String   | URL to view the security rule in Datadog UI.                                      |
| Datadog.SecuritySignal.triage.state           | String   | The current triage state of the security signal \(open, under_review, archived\). |
| Datadog.SecuritySignal.triage.archive_comment | String   | The archive comment of the security signal.                                       |
| Datadog.SecuritySignal.triage.archive_reason  | String   | The archive reason of the security signal.                                        |
| Datadog.SecuritySignal.triage.assignee.name   | String   | The name of the user assigned to the security signal.                             |
| Datadog.SecuritySignal.triage.assignee.handle | String   | The handle of the user assigned to the security signal.                           |
| Datadog.SecuritySignal.raw                    | Unknown  | The raw signal object returned by the API.                                        |

#### Command example

`!datadog-signal-update signal_id=AZm-wsEuAACEnzdcj-YEigAA state=archived archive_reason=false_positive archive_comment="Not a real threat"`

`!datadog-signal-update assignee=user@example.com`

`!datadog-signal-update state=under_review`

---

### datadog-signal-comment-add

---

Add a comment to a security signal in Datadog Cloud SIEM V2.

#### Base Command

`datadog-signal-comment-add`

#### Input

| **Argument Name** | **Description**                                                                                                             | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------- | ------------ |
| event_id          | The event ID of the security signal to add a comment to. If not provided, will attempt to get it from the current incident. | Optional     |
| comment           | The comment text to add to the security signal.                                                                             | Required     |

#### Context Output

| **Path**                            | **Type** | **Description**                                 |
| ----------------------------------- | -------- | ----------------------------------------------- |
| Datadog.SecurityComment.id          | String   | The unique identifier of the comment.           |
| Datadog.SecurityComment.created_at  | String   | The timestamp when the comment was created.     |
| Datadog.SecurityComment.user_uuid   | String   | The UUID of the user who created the comment.   |
| Datadog.SecurityComment.text        | String   | The comment text content.                       |
| Datadog.SecurityComment.user.name   | String   | The name of the user who created the comment.   |
| Datadog.SecurityComment.user.handle | String   | The handle of the user who created the comment. |

#### Command example

`!datadog-signal-comment-add event_id=AZm-wsEuAACEnzdcj-YEigAA comment="Investigating this signal"`

`!datadog-signal-comment-add comment="False positive confirmed"`

---

### datadog-signal-comment-list

---

List all comments for a security signal in Datadog Cloud SIEM V2.

#### Base Command

`datadog-signal-comment-list`

#### Input

| **Argument Name** | **Description**                                                                                                              | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------ |
| event_id          | The event ID of the security signal to list comments for. If not provided, will attempt to get it from the current incident. | Optional     |

#### Context Output

| **Path**                            | **Type** | **Description**                                 |
| ----------------------------------- | -------- | ----------------------------------------------- |
| Datadog.SecurityComment.id          | String   | The unique identifier of the comment.           |
| Datadog.SecurityComment.created_at  | String   | The timestamp when the comment was created.     |
| Datadog.SecurityComment.user_uuid   | String   | The UUID of the user who created the comment.   |
| Datadog.SecurityComment.text        | String   | The comment text content.                       |
| Datadog.SecurityComment.user.name   | String   | The name of the user who created the comment.   |
| Datadog.SecurityComment.user.handle | String   | The handle of the user who created the comment. |

#### Command example

`!datadog-signal-comment-list event_id=AZm-wsEuAACEnzdcj-YEigAA`

`!datadog-signal-comment-list`

---

### datadog-rule-suppress

---

Create a suppression rule for a security monitoring rule to exclude signals from generating alerts. Useful for filtering out known false positives or signals from testing environments.

#### Base Command

`datadog-rule-suppress`

#### Input

| **Argument Name**    | **Description**                                                                                                         | **Required** |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------ |
| rule_id              | The ID of the security rule to suppress. If not provided, will attempt to get it from the current incident.             | Optional     |
| data_exclusion_query | Query to match signals to suppress. Uses Datadog search syntax. Default is "\*" to suppress all signals from this rule. | Optional     |

#### Context Output

There is no context output for this command.

#### Command example

`!datadog-rule-suppress rule_id=abc-123-def data_exclusion_query="env:staging"`

`!datadog-rule-suppress data_exclusion_query="host:test-*"`

---

### datadog-rule-unsuppress

---

Disable all active suppressions affecting a security monitoring rule, re-enabling alerts for that rule.

#### Base Command

`datadog-rule-unsuppress`

#### Input

| **Argument Name** | **Description**                                                                                               | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------- | ------------ |
| rule_id           | The ID of the security rule to unsuppress. If not provided, will attempt to get it from the current incident. | Optional     |

#### Context Output

There is no context output for this command.

#### Command example

`!datadog-rule-unsuppress rule_id=abc-123-def`

`!datadog-rule-unsuppress`

---

### datadog-rule-get

---

Get a specific security monitoring rule by ID from Datadog Cloud SIEM V2.

#### Base Command

`datadog-rule-get`

#### Input

| **Argument Name** | **Description**                                                                                                            | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------ |
| rule_id           | The unique identifier of the security rule to retrieve. If not provided, will attempt to get it from the current incident. | Optional     |

#### Context Output

| **Path**                       | **Type** | **Description**                                    |
| ------------------------------ | -------- | -------------------------------------------------- |
| Datadog.SecurityRule.id        | String   | The unique identifier of the security rule.        |
| Datadog.SecurityRule.name      | String   | The name of the security rule.                     |
| Datadog.SecurityRule.type      | String   | The type of the security rule.                     |
| Datadog.SecurityRule.isEnabled | Boolean  | Whether the security rule is enabled.              |
| Datadog.SecurityRule.createdAt | String   | Timestamp when the rule was created.               |
| Datadog.SecurityRule.message   | String   | Message for the security rule.                     |
| Datadog.SecurityRule.queries   | Unknown  | Queries associated with the security rule.         |
| Datadog.SecurityRule.cases     | Unknown  | Cases \(severity and notifications\) for the rule. |
| Datadog.SecurityRule.options   | Unknown  | Options for the security rule.                     |
| Datadog.SecurityRule.tags      | Unknown  | Tags associated with the security rule.            |
| Datadog.SecurityRule.url       | String   | URL to view the security rule in Datadog UI.       |
| Datadog.SecurityRule.raw       | Unknown  | The raw rule object returned by the API.           |

#### Command example

`!datadog-rule-get rule_id=abc-123-def`

`!datadog-rule-get`

---

### datadog-logs-query

---

Query logs in Datadog Cloud SIEM V2 with optional filtering for security investigations.

#### Base Command

`datadog-logs-query`

#### Input

| **Argument Name** | **Description**                                                                                                                                                        | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| query             | Custom search query string. Uses Datadog search syntax. Required unless running from an incident with a Datadog Security Signal \(will use rule's query as fallback\). | Optional     |
| from_date         | Start date for the search. Format can be relative \(e.g., "7 days ago"\) or absolute \(e.g., "2023-01-01T00:00:00Z"\). Default: -7days.                                | Optional     |
| to_date           | End date for the search. Format can be relative \(e.g., "now"\) or absolute \(e.g., "2023-01-01T23:59:59Z"\). Default: now.                                            | Optional     |
| sort              | Sort order for results. Possible values are: asc, desc. Default: desc.                                                                                                 | Optional     |
| limit             | Maximum number of results to return. Default: 50.                                                                                                                      | Optional     |

#### Context Output

| **Path**              | **Type** | **Description**                             |
| --------------------- | -------- | ------------------------------------------- |
| Datadog.Log.id        | String   | The unique identifier of the log entry.     |
| Datadog.Log.timestamp | String   | The timestamp when the log was generated.   |
| Datadog.Log.message   | String   | The log message content.                    |
| Datadog.Log.service   | String   | The service that generated the log.         |
| Datadog.Log.host      | String   | The host that generated the log.            |
| Datadog.Log.source    | String   | The source of the log entry.                |
| Datadog.Log.status    | String   | The status/level of the log entry.          |
| Datadog.Log.tags      | Unknown  | List of tags associated with the log entry. |
| Datadog.Log.url       | String   | URL to view the log in Datadog UI.          |
| Datadog.Log.raw       | Unknown  | The raw log object returned by the API.     |

#### Command example

`!datadog-logs-query query="source:nginx status:error" from_date="-1hour" limit=50`

`!datadog-logs-query`

---

## Incident Fetching

This integration supports fetching security signals from Datadog Cloud SIEM V2 as Cortex XSOAR incidents.

### Configuration

To enable incident fetching:

1. In the integration instance configuration, check **Fetch incidents**.
2. Configure the following parameters:
    - **First fetch time**: How far back to fetch signals on first run (e.g., "3 days", "7 days")
    - **Max fetch**: Maximum incidents per fetch cycle (recommended: 50, max: 200)
    - **Fetch severity**: Comma-separated list of severities to fetch (leave empty for all)
    - **Fetch state**: Signal state to fetch (default: "open")
    - **Fetch query**: Additional custom filter query (optional)
3. Set the **Incident type** if you want to classify fetched incidents.

### Incident Fields

Each fetched incident includes:

-   **Name**: Security signal title
-   **Occurred**: Signal timestamp
-   **Severity**: Mapped from Datadog severity (Low=1, Medium=2, High=3, Critical=4)
-   **Raw JSON**: Complete signal data for mapping and enrichment

## Troubleshooting

### Authentication Errors

-   Verify API Key and APP Key are correct
-   Ensure keys have appropriate permissions in Datadog
-   Check Server URL matches your Datadog site (e.g., datadoghq.com, datadoghq.eu)

### Fetch Issues

-   Check First Fetch Time is not too far in the past (max 90 days recommended)
-   Verify Fetch Query syntax using Datadog's query language
-   Review integration logs for detailed error messages
