# Datadog Cloud SIEM

Datadog Cloud SIEM integration for Cortex XSOAR provides security signal management and log search capabilities for threat detection and incident response.

This integration allows security teams to:

- Fetch security signals as XSOAR incidents automatically
- Retrieve and filter security signals from Datadog's Cloud SIEM platform
- Manage signal triage states and assignments
- Search security logs for investigations
- Extract IOCs (IPs, URLs, file hashes) from security signals

This integration was integrated and tested with version 2.12.0 of datadog-api-client.

## Configure Datadog Cloud SIEM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Instances**.
2. Search for Datadog Cloud SIEM.
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

### datadog-get-signal

---

Get a specific security signal by ID from Datadog Cloud SIEM.

##### Base Command

`datadog-get-signal`

##### Input

| **Argument Name** | **Description**                                                                                                              | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------ |
| signal_id         | The unique identifier of the security signal to retrieve. If not provided, will attempt to get it from the current incident. | Optional     |

##### Context Output

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

##### Command example

`!datadog-get-signal signal_id=AZm-wsEuAACEnzdcj-YEigAA`

`!datadog-get-signal`

---

### datadog-list-signals

---

Get a list of security signals from Datadog Cloud SIEM with optional filtering and pagination.

##### Base Command

`datadog-list-signals`

##### Input

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

##### Context Output

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

##### Command example

`!datadog-list-signals state=open severity=high`

`!datadog-list-signals from_date="-3days" to_date="now" limit=10`

---

### datadog-update-signal-state

---

Update a security signal's assignee and/or state in Datadog Cloud SIEM. Can update assignee only, state only, or both in a single command.

##### Base Command

`datadog-update-signal-state`

##### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                      | **Required** |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------ |
| signal_id         | The unique identifier of the security signal to update. If not provided, will attempt to get it from the current incident.                                                                                                           | Optional     |
| assignee          | Name or email of the user to assign to the security signal. Leave empty to unassign. At least one of assignee or state must be provided.                                                                                             | Optional     |
| state             | The new state of the security signal. Possible values are: open, under_review, archived. At least one of assignee or state must be provided.                                                                                         | Optional     |
| archive_reason    | Reason for the state change \(used when changing state to archived\). Possible values are: none, false_positive, testing_or_maintenance, remediated, investigated_case_opened, other, true_positive_benign, true_positive_malicious. | Optional     |
| archive_comment   | Comment about the state change \(used when changing state to archived\).                                                                                                                                                             | Optional     |

##### Context Output

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

##### Command example

`!datadog-update-signal-state signal_id=AZm-wsEuAACEnzdcj-YEigAA state=archived archive_reason=false_positive archive_comment="Not a real threat"`

`!datadog-update-signal-state assignee=user@example.com`

`!datadog-update-signal-state state=under_review`

---

### datadog-add-signal-comment

---

Add a comment to a security signal in Datadog Cloud SIEM.

##### Base Command

`datadog-add-signal-comment`

##### Input

| **Argument Name** | **Description**                                                                                                             | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------- | ------------ |
| event_id          | The event ID of the security signal to add a comment to. If not provided, will attempt to get it from the current incident. | Optional     |
| comment           | The comment text to add to the security signal.                                                                             | Required     |

##### Context Output

| **Path**                            | **Type** | **Description**                                 |
| ----------------------------------- | -------- | ----------------------------------------------- |
| Datadog.SecurityComment.id          | String   | The unique identifier of the comment.           |
| Datadog.SecurityComment.created_at  | String   | The timestamp when the comment was created.     |
| Datadog.SecurityComment.user_uuid   | String   | The UUID of the user who created the comment.   |
| Datadog.SecurityComment.text        | String   | The comment text content.                       |
| Datadog.SecurityComment.user.name   | String   | The name of the user who created the comment.   |
| Datadog.SecurityComment.user.handle | String   | The handle of the user who created the comment. |

##### Command example

`!datadog-add-signal-comment event_id=AZm-wsEuAACEnzdcj-YEigAA comment="Investigating this signal"`

`!datadog-add-signal-comment comment="False positive confirmed"`

---

### datadog-list-signal-comments

---

List all comments for a security signal in Datadog Cloud SIEM.

##### Base Command

`datadog-list-signal-comments`

##### Input

| **Argument Name** | **Description**                                                                                                              | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------ |
| event_id          | The event ID of the security signal to list comments for. If not provided, will attempt to get it from the current incident. | Optional     |

##### Context Output

| **Path**                            | **Type** | **Description**                                 |
| ----------------------------------- | -------- | ----------------------------------------------- |
| Datadog.SecurityComment.id          | String   | The unique identifier of the comment.           |
| Datadog.SecurityComment.created_at  | String   | The timestamp when the comment was created.     |
| Datadog.SecurityComment.user_uuid   | String   | The UUID of the user who created the comment.   |
| Datadog.SecurityComment.text        | String   | The comment text content.                       |
| Datadog.SecurityComment.user.name   | String   | The name of the user who created the comment.   |
| Datadog.SecurityComment.user.handle | String   | The handle of the user who created the comment. |

##### Command example

`!datadog-list-signal-comments event_id=AZm-wsEuAACEnzdcj-YEigAA`

`!datadog-list-signal-comments`

---

### datadog-get-rule

---

Get a specific security monitoring rule by ID from Datadog Cloud SIEM.

##### Base Command

`datadog-get-rule`

##### Input

| **Argument Name** | **Description**                                                                                                            | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------ |
| rule_id           | The unique identifier of the security rule to retrieve. If not provided, will attempt to get it from the current incident. | Optional     |

##### Context Output

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

##### Command example

`!datadog-get-rule rule_id=abc-123-def`

`!datadog-get-rule`

---

### datadog-query-logs

---

Query logs in Datadog Cloud SIEM with optional filtering for security investigations.

##### Base Command

`datadog-query-logs`

##### Input

| **Argument Name** | **Description**                                                                                                                                                        | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| query             | Custom search query string. Uses Datadog search syntax. Required unless running from an incident with a Datadog Security Signal \(will use rule's query as fallback\). | Optional     |
| from_date         | Start date for the search. Format can be relative \(e.g., "7 days ago"\) or absolute \(e.g., "2023-01-01T00:00:00Z"\). Default: -7days.                                | Optional     |
| to_date           | End date for the search. Format can be relative \(e.g., "now"\) or absolute \(e.g., "2023-01-01T23:59:59Z"\). Default: now.                                            | Optional     |
| sort              | Sort order for results. Possible values are: asc, desc. Default: desc.                                                                                                 | Optional     |
| limit             | Maximum number of results to return. Default: 50.                                                                                                                      | Optional     |

##### Context Output

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

##### Command example

`!datadog-query-logs query="source:nginx status:error" from_date="-1hour" limit=50`

`!datadog-query-logs`

---

### datadog-update-signal-assignee

---

Update a security signal's assignee in Datadog Cloud SIEM.

##### Base Command

`datadog-update-signal-assignee`

##### Input

| **Argument Name** | **Description**                                                                                                            | **Required** |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------ |
| signal_id         | The unique identifier of the security signal to update. If not provided, will attempt to get it from the current incident. | Optional     |
| assignee          | Name or email of the user to assign to the security signal. Leave empty to unassign.                                       | Optional     |

##### Context Output

Same as datadog-get-signal command.

##### Command example

`!datadog-update-signal-assignee signal_id=AZm-wsEuAACEnzdcj-YEigAA assignee=user@example.com`

`!datadog-update-signal-assignee assignee=""`

---

### datadog-update-suppression

---

Update an existing suppression rule by ID.

##### Base Command

`datadog-update-suppression`

##### Input

| **Argument Name** | **Description**                                      | **Required** |
| ----------------- | ---------------------------------------------------- | ------------ |
| rule_id           | The unique identifier of the suppression rule.        | Required     |
| enabled           | Enable or disable the suppression rule.              | Optional     |
| name              | New name for the suppression rule.                   | Optional     |
| description       | New description for the suppression rule.            | Optional     |
| data_exclusion_query | New data exclusion query for the suppression rule. | Optional     |

##### Context Output

Same as datadog-get-rule command.

##### Command example

`!datadog-update-suppression rule_id=abc-123 enabled=false`

---

### datadog-list-suppressions

---

List all suppressions affecting a specific security monitoring rule.

##### Base Command

`datadog-list-suppressions`

##### Input

| **Argument Name** | **Description**                                     | **Required** |
| ----------------- | --------------------------------------------------- | ------------ |
| rule_id           | The unique identifier of the security rule.         | Required     |

##### Context Output

Returns list of suppression rules associated with the specified rule.

##### Command example

`!datadog-list-suppressions rule_id=abc-123`

---

### datadog-list-security-filters

---

List all security filters from Datadog Cloud SIEM.

##### Base Command

`datadog-list-security-filters`

##### Input

There are no input arguments for this command.

##### Context Output

Returns list of security filters.

##### Command example

`!datadog-list-security-filters`

---

### datadog-list-signal-notification-rules

---

List all signal notification rules from Datadog Cloud SIEM.

##### Base Command

`datadog-list-signal-notification-rules`

##### Input

There are no input arguments for this command.

##### Context Output

Returns list of signal notification rules.

##### Command example

`!datadog-list-signal-notification-rules`

---

### datadog-list-vulnerability-notification-rules

---

List all vulnerability notification rules from Datadog Cloud SIEM.

##### Base Command

`datadog-list-vulnerability-notification-rules`

##### Input

There are no input arguments for this command.

##### Context Output

Returns list of vulnerability notification rules.

##### Command example

`!datadog-list-vulnerability-notification-rules`

---

### datadog-bitsai-get-investigation

---

Get the BitsAI investigation for a security signal.

##### Base Command

`datadog-bitsai-get-investigation`

##### Input

| **Argument Name** | **Description**                                     | **Required** |
| ----------------- | --------------------------------------------------- | ------------ |
| signal_id         | The unique identifier of the security signal.       | Required     |

##### Context Output

Returns BitsAI investigation analysis for the signal.

##### Command example

`!datadog-bitsai-get-investigation signal_id=AZm-wsEuAACEnzdcj-YEigAA`

---

### datadog-list-risk-scores

---

List risk scores from Datadog Cloud SIEM.

##### Base Command

`datadog-list-risk-scores`

##### Input

| **Argument Name** | **Description**                                          | **Required** |
| ----------------- | -------------------------------------------------------- | ------------ |
| entity            | Filter by entity name or identifier.                     | Optional     |
| from_date         | Start date for the risk score query.                     | Optional     |
| to_date           | End date for the risk score query.                       | Optional     |
| limit             | Maximum number of risk scores to return. Default is 100. | Optional     |

##### Context Output

Returns list of risk scores for monitored entities.

##### Command example

`!datadog-list-risk-scores limit=50`

---

## Incident Fetching

This integration supports fetching security signals from Datadog Cloud SIEM as Cortex XSOAR incidents.

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

- **Name**: Security signal title
- **Occurred**: Signal timestamp
- **Severity**: Mapped from Datadog severity (Low=1, Medium=2, High=3, Critical=4)
- **Raw JSON**: Complete signal data for mapping and enrichment

## Troubleshooting

### Authentication Errors

- Verify API Key and APP Key are correct
- Ensure keys have appropriate permissions in Datadog
- Check Server URL matches your Datadog site (e.g., datadoghq.com, datadoghq.eu)

### Fetch Issues

- Check First Fetch Time is not too far in the past (max 90 days recommended)
- Verify Fetch Query syntax using Datadog's query language
- Review integration logs for detailed error messages
