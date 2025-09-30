# Datadog Cloud SIEM

Datadog Cloud SIEM integration for Cortex XSOAR provides security signal management and log search capabilities for threat detection and incident response.

This integration allows security teams to:

-   Fetch security signals as XSOAR incidents automatically
-   Retrieve and filter security signals from Datadog's Cloud SIEM platform
-   Manage signal triage states and assignments
-   Search security logs for investigations
-   Extract IOCs (IPs, URLs, file hashes) from security signals

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

### datadog-security-signal-get

---

Retrieves a specific security signal by ID from Datadog Cloud SIEM, including automatic extraction of IOCs (IP addresses, URLs, and file hashes).

#### Base Command

`datadog-security-signal-get`

#### Input

| **Argument Name** | **Description**                                           | **Required** |
| ----------------- | --------------------------------------------------------- | ------------ |
| signal_id         | The unique identifier of the security signal to retrieve. | Required     |

#### Context Output

| **Path**                                    | **Type** | **Description**                                            |
| ------------------------------------------- | -------- | ---------------------------------------------------------- |
| Datadog.SecuritySignal.id                   | String   | The unique identifier of the security signal.              |
| Datadog.SecuritySignal.timestamp            | String   | The timestamp when the security signal was generated.      |
| Datadog.SecuritySignal.title                | String   | The title of the security signal.                          |
| Datadog.SecuritySignal.message              | String   | The message describing the security signal.                |
| Datadog.SecuritySignal.severity             | String   | The severity level \(info, low, medium, high, critical\).  |
| Datadog.SecuritySignal.host                 | String   | Host associated with the security signal.                  |
| Datadog.SecuritySignal.service              | Unknown  | List of services associated with the security signal.      |
| Datadog.SecuritySignal.tags                 | Unknown  | List of tags associated with the security signal.          |
| Datadog.SecuritySignal.triggering_log_id    | String   | ID of the log that triggered the security signal.          |
| Datadog.SecuritySignal.rule.id              | String   | The unique identifier of the security rule.                |
| Datadog.SecuritySignal.rule.name            | String   | The name of the security rule that triggered the signal.   |
| Datadog.SecuritySignal.rule.type            | String   | The type of the security rule.                             |
| Datadog.SecuritySignal.rule.tags            | Unknown  | List of tags associated with the security rule.            |
| Datadog.SecuritySignal.triage.state         | String   | The current triage state \(open, under_review, archived\). |
| Datadog.SecuritySignal.triage.comment       | String   | The archive comment of the security signal.                |
| Datadog.SecuritySignal.triage.reason        | String   | The archive reason of the security signal.                 |
| Datadog.SecuritySignal.triage.assignee.id   | Number   | The ID of the user assigned to the security signal.        |
| Datadog.SecuritySignal.triage.assignee.uuid | String   | The UUID of the user assigned to the security signal.      |
| Datadog.SecuritySignal.triage.assignee.name | String   | The name of the user assigned to the security signal.      |
| Datadog.SecuritySignal.raw                  | Unknown  | The raw signal object returned by the API.                 |

#### Command example

`!datadog-security-signal-get signal_id="AQAAAYZIXXXXXXXX"`

#### Context Example

```json
[TO BE COMPLETED WITH ACTUAL OUTPUT]
```

#### Human Readable Output

> [TO BE COMPLETED WITH ACTUAL OUTPUT]

---

### datadog-security-signals-list

---

Retrieves a list of security signals from Datadog Cloud SIEM with optional filtering by state, severity, time range, and custom queries. Automatically extracts IOCs from all returned signals.

#### Base Command

`datadog-security-signals-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                 | **Required** |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| state             | Filter signals by triage state. Possible values are: open, under_review, archived.                                                                              | Optional     |
| severity          | Filter signals by severity level. Possible values are: info, low, medium, high, critical.                                                                       | Optional     |
| rule_name         | Filter signals by rule name (exact match).                                                                                                                      | Optional     |
| source            | Filter signals by source.                                                                                                                                       | Optional     |
| query             | Custom query string for advanced filtering using Datadog search syntax.                                                                                         | Optional     |
| from_date         | Start date for the search. Supports relative formats (e.g., "7 days ago", "-7days") or absolute ISO format (e.g., "2023-01-01T00:00:00Z"). Default is "-7days". | Optional     |
| to_date           | End date for the search. Supports relative formats (e.g., "now") or absolute ISO format. Default is "now".                                                      | Optional     |
| sort              | Sort order for results. Possible values are: asc, desc. Default is desc.                                                                                        | Optional     |
| page_size         | Number of results per page.                                                                                                                                     | Optional     |
| limit             | Maximum number of results to return. If page_size is specified, limit is ignored. Default is 50.                                                                | Optional     |

#### Context Output

| **Path**                                    | **Type** | **Description**                                            |
| ------------------------------------------- | -------- | ---------------------------------------------------------- |
| Datadog.SecuritySignal.id                   | String   | The unique identifier of the security signal.              |
| Datadog.SecuritySignal.timestamp            | String   | The timestamp when the security signal was generated.      |
| Datadog.SecuritySignal.title                | String   | The title of the security signal.                          |
| Datadog.SecuritySignal.message              | String   | The message describing the security signal.                |
| Datadog.SecuritySignal.severity             | String   | The severity level \(info, low, medium, high, critical\).  |
| Datadog.SecuritySignal.host                 | String   | Host associated with the security signal.                  |
| Datadog.SecuritySignal.service              | Unknown  | List of services associated with the security signal.      |
| Datadog.SecuritySignal.tags                 | Unknown  | List of tags associated with the security signal.          |
| Datadog.SecuritySignal.triggering_log_id    | String   | ID of the log that triggered the security signal.          |
| Datadog.SecuritySignal.rule.id              | String   | The unique identifier of the security rule.                |
| Datadog.SecuritySignal.rule.name            | String   | The name of the security rule that triggered the signal.   |
| Datadog.SecuritySignal.rule.type            | String   | The type of the security rule.                             |
| Datadog.SecuritySignal.rule.tags            | Unknown  | List of tags associated with the security rule.            |
| Datadog.SecuritySignal.triage.state         | String   | The current triage state \(open, under_review, archived\). |
| Datadog.SecuritySignal.triage.comment       | String   | The archive comment of the security signal.                |
| Datadog.SecuritySignal.triage.reason        | String   | The archive reason of the security signal.                 |
| Datadog.SecuritySignal.triage.assignee.id   | Number   | The ID of the user assigned to the security signal.        |
| Datadog.SecuritySignal.triage.assignee.uuid | String   | The UUID of the user assigned to the security signal.      |
| Datadog.SecuritySignal.triage.assignee.name | String   | The name of the user assigned to the security signal.      |
| Datadog.SecuritySignal.raw                  | Unknown  | The raw signal object returned by the API.                 |

#### Command example

`!datadog-security-signals-list state=open severity=high limit=10`

#### Context Example

```json
[TO BE COMPLETED WITH ACTUAL OUTPUT]
```

#### Human Readable Output

> [TO BE COMPLETED WITH ACTUAL OUTPUT]

---

### datadog-security-signal-assignee-update

---

Updates the assignee of a security signal in Datadog Cloud SIEM. Assign signals to team members for investigation and response.

#### Base Command

`datadog-security-signal-assignee-update`

#### Input

| **Argument Name** | **Description**                                                                 | **Required** |
| ----------------- | ------------------------------------------------------------------------------- | ------------ |
| signal_id         | The unique identifier of the security signal to update.                         | Required     |
| assignee_uuid     | The UUID of the user to assign to the security signal. Leave empty to unassign. | Optional     |

#### Context Output

| **Path**                                    | **Type** | **Description**                                            |
| ------------------------------------------- | -------- | ---------------------------------------------------------- |
| Datadog.SecuritySignal.triage.state         | String   | The current triage state \(open, under_review, archived\). |
| Datadog.SecuritySignal.triage.comment       | String   | The archive comment of the security signal.                |
| Datadog.SecuritySignal.triage.reason        | String   | The archive reason of the security signal.                 |
| Datadog.SecuritySignal.triage.assignee.uuid | String   | The UUID of the user assigned to the security signal.      |
| Datadog.SecuritySignal.triage.assignee.name | String   | The name of the user assigned to the security signal.      |

#### Command example

`!datadog-security-signal-assignee-update signal_id="AQAAAYZIXXXXXXXX" assignee_uuid="00000000-0000-0000-0000-000000000000"`

#### Context Example

```json
[TO BE COMPLETED WITH ACTUAL OUTPUT]
```

#### Human Readable Output

> [TO BE COMPLETED WITH ACTUAL OUTPUT]

---

### datadog-security-signal-state-update

---

Updates the triage state of a security signal in Datadog Cloud SIEM. Manage signal lifecycle by transitioning between open, under review, and archived states.

#### Base Command

`datadog-security-signal-state-update`

#### Input

| **Argument Name** | **Description**                                                                         | **Required** |
| ----------------- | --------------------------------------------------------------------------------------- | ------------ |
| signal_id         | The unique identifier of the security signal to update.                                 | Required     |
| state             | The new triage state for the signal. Possible values are: open, under_review, archived. | Required     |
| reason            | Reason for the state change (especially important when archiving signals).              | Optional     |
| comment           | Additional comment about the state change.                                              | Optional     |

#### Context Output

| **Path**                                    | **Type** | **Description**                                            |
| ------------------------------------------- | -------- | ---------------------------------------------------------- |
| Datadog.SecuritySignal.triage.state         | String   | The current triage state \(open, under_review, archived\). |
| Datadog.SecuritySignal.triage.comment       | String   | The archive comment of the security signal.                |
| Datadog.SecuritySignal.triage.reason        | String   | The archive reason of the security signal.                 |
| Datadog.SecuritySignal.triage.assignee.uuid | String   | The UUID of the user assigned to the security signal.      |
| Datadog.SecuritySignal.triage.assignee.name | String   | The name of the user assigned to the security signal.      |

#### Command example

`!datadog-security-signal-state-update signal_id="AQAAAYZIXXXXXXXX" state="archived" reason="false_positive" comment="Benign activity confirmed"`

#### Context Example

```json
[TO BE COMPLETED WITH ACTUAL OUTPUT]
```

#### Human Readable Output

> [TO BE COMPLETED WITH ACTUAL OUTPUT]

---

### datadog-logs-search

---

Searches for logs in Datadog with optional filtering by service, host, source, status, and time range. Useful for security investigations and threat hunting.

#### Base Command

`datadog-logs-search`

#### Input

| **Argument Name** | **Description**                                                                                                        | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------ |
| query             | Custom search query string using Datadog search syntax.                                                                | Optional     |
| service           | Filter logs by service name.                                                                                           | Optional     |
| host              | Filter logs by host name.                                                                                              | Optional     |
| source            | Filter logs by source.                                                                                                 | Optional     |
| status            | Filter logs by status/level (info, warn, error, debug, etc.).                                                          | Optional     |
| from_date         | Start date for the search. Supports relative formats (e.g., "7 days ago") or absolute ISO format. Default is "-7days". | Optional     |
| to_date           | End date for the search. Supports relative formats (e.g., "now") or absolute ISO format. Default is "now".             | Optional     |
| sort              | Sort order for results. Possible values are: asc, desc. Default is desc.                                               | Optional     |
| page_size         | Number of results per page.                                                                                            | Optional     |
| limit             | Maximum number of results to return. If page_size is specified, limit is ignored. Default is 50.                       | Optional     |

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
| Datadog.Log.raw       | Unknown  | The raw log object returned by the API.     |

#### Command example

`!datadog-logs-search service="web-api" status="error" limit=20`

#### Context Example

```json
[TO BE COMPLETED WITH ACTUAL OUTPUT]
```

#### Human Readable Output

> [TO BE COMPLETED WITH ACTUAL OUTPUT]

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

-   **Name**: Security signal title
-   **Occurred**: Signal timestamp
-   **Severity**: Mapped from Datadog severity (Low=1, Medium=2, High=3, Critical=4)
-   **Raw JSON**: Complete signal data for mapping and enrichment

### IOC Extraction

IOCs are automatically extracted from security signals and can be accessed via:

-   Running `!datadog-security-signal-get signal_id=${incident.dbotMirrorId}` in playbooks
-   Standard XSOAR indicator contexts (IP, URL, File) are populated

## Known Limitations

-   Private IP addresses (RFC 1918) are filtered out from IOC extraction
-   Datadog API rate limits apply

## Troubleshooting

### Authentication Errors

-   Verify API Key and APP Key are correct
-   Ensure keys have appropriate permissions in Datadog
-   Check Server URL matches your Datadog site (e.g., datadoghq.com, datadoghq.eu)

### Fetch Issues

-   Check First Fetch Time is not too far in the past (max 90 days recommended)
-   Verify Fetch Query syntax using Datadog's query language
-   Review integration logs for detailed error messages

### IOC Extraction

-   IOCs are extracted from signal title, message, tags, and raw data
-   Only public IP addresses are extracted (private IPs filtered)
-   File hashes must be complete MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars)
