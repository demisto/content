For integration with the Secureworks Taegis XDR platform.
This integration was integrated and tested with version xx of TaegisXDRv3.

## Configure Taegis XDR v3 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Client ID | The Client ID from the Taegis XDR API credential this instance should authenticate as. | True |
| Client Secret | The Client Secret generated alongside the Client ID. Taegis displays it only once, at creation. | True |
| API base URL | Taegis API base URL for your environment. Do not include a trailing slash. Required for all commands. | False |
| XDR base URL | Taegis XDR \(UI\) base URL for your environment. Used for investigation/alert links. Do not include a trailing slash. Required for all commands. | False |
| Tenant ID | Optional. Leave blank if the credential is scoped to a single tenant. For multi-tenant credentials, supply the Tenant ID this instance should act against. | False |
| Trust any certificate (not secure) | Skip verification of the Taegis API server's TLS certificate. Not recommended outside troubleshooting. | False |
| Use system proxy settings | Route requests through the system proxy configured on the Cortex XSOAR server. | False |
| Fetch incidents | Enable to ingest Taegis XDR cases into Cortex XSOAR as incidents on each fetch interval. | False |
| Incident type | The Cortex XSOAR incident type applied to ingested cases. Leave as Taegis XDR - Case unless you have created a custom type. | False |
| Maximum number of incidents per fetch | The maximum limit is 200. | False |
| Incidents Fetch Interval | The interval in minutes to fetch incidents. The default is 1 minute. | False |
| First fetch timestamp | How far back to look for cases on the first fetch only, expressed as &lt;number&gt; &lt;time unit&gt;, for example 1 day, 12 hours, or 7 days. Later fetches resume from the previous run. | False |
| Fetch Incident Type | The type of incidents to fetch. The default is investigations. | False |
| Include Assets in Fetch | Include associated asset details when fetching. Enriches the incident but increases fetch duration. | False |
| Fetch investigations - exclusion list (assignee emails or names) | EXCLUSION LIST: Comma-separated assignee emails, display names, or assignee IDs \(e.g. user@domain.com, Sophos, auth0\|xxx\). Investigations assigned to any matching assignee are EXCLUDED \(no Cortex XSOAR incident\). Match is by email, name, or assignee_id. If a team name \(e.g. Sophos\) does not match, check debug logs for assignee_id and add that ID to this list. Leave empty to fetch all. | False |
| Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from Taegis XDR to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to Taegis XDR\), or Incoming And Outgoing \(bidirectional\). | False |
| Comment Entry Tag To Taegis | Choose the tag to add to an entry to mirror it as a comment in Taegis XDR. | False |
| Comment Entry Tag From Taegis | Choose the tag to add to an entry to mirror it as a comment from Taegis XDR. | False |
| Close Cortex XSOAR incident when Taegis investigation is closed | When enabled, closing a Taegis investigation \(status starting with CLOSED_\) will close the mirrored incident in Cortex XSOAR. | False |
| Use closeInvestigation when Taegis XDR Case Status is set to closed | When enabled, setting Taegis XDR Case Status \(taegisxdrcasestatus\) to a closed value \(e.g. CLOSED_INCONCLUSIVE\) will close the investigation in Taegis via the closeInvestigation mutation \(with reason\). Cortex XSOAR incident status is not used to close Taegis. | False |
| How many investigations to mirror incoming each time | If a greater number of investigations than the limit were modified, then they won't all be mirrored in a single run. | False |
| Timestamp field to query for updates as part of the mirroring flow | Field used to determine when an investigation was last updated for mirroring. Default is updated_at. The investigationsSearch GraphQL API uses the Investigation type with snake_case \(updated_at\). Taegis v2 docs may show updatedAt for investigationV2/investigationsV2; use updated_at for investigationsSearch. | False |
| Cortex XSOAR Taegis XDR Key Findings is master | When enabled, Cortex XSOAR "Taegis XDR Key Findings" \(taegisxdrkeyfindings\) is always pushed to Taegis Key Findings on every update \(Cortex XSOAR is master\). When disabled \(default\), Key Findings are only pushed when the user explicitly changes that field in Cortex XSOAR, so Taegis edits are not overwritten \(bidirectional-friendly\). | False |
| Assign case to Sophos MDR team after comment | When enabled, the "Assign case to Sophos MDR team" field in the Add Comment form defaults to "Yes". When disabled \(default\), the field defaults to "No". Users can still override per comment to "Yes" or "No". | False |
| Archive Taegis XDR case on close | When enabled, the "Taegis XDR Archive on Close" checkbox defaults to checked in the Close Incident panel. When disabled \(default\), the checkbox is unchecked. Archiving removes the case from the active Taegis XDR case list. Users can override this per incident at close time. | False |
| Allow reopen of archived Taegis XDR cases | When enabled, reopening a closed Cortex XSOAR incident will automatically unarchive the associated Taegis XDR case before setting it back to ACTIVE. When disabled \(default\), archived cases cannot be reopened via Cortex XSOAR; the case must be unarchived manually in Taegis XDR first. | False |
| Retry on Taegis API rate limit (429) | When enabled, GraphQL and auth requests that receive HTTP 429 \(rate limit\) are retried with backoff. Helps when closing many mirrored incidents at once. Uses Retry-After when Taegis returns it. | False |
| Max retries on API rate limit | Retry attempts after a 429 \(in addition to the first request\). Range 0-10. Each wait uses Retry-After or exponential backoff. | False |
| Base delay (seconds) for rate-limit backoff | When Retry-After is absent, wait base x 2^attempt seconds before each retry \(capped per wait\). | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### taegis-fetch-investigation

***
Fetch a specific investigation or list of investigations.

#### Base Command

`taegis-fetch-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required |
| tenant_id | Tenant ID. | Optional |

#### Context Output

There is no context output for this command.

### taegis-fetch-comments

***
Fetch comments by Investigation ID.

#### Base Command

`taegis-fetch-comments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required |
| tenant_id | Tenant ID. | Optional |

#### Context Output

There is no context output for this command.

### taegis-create-comment

***
Create a comment on an investigation.

#### Base Command

`taegis-create-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required |
| comment | Comment text. | Required |
| tenant_id | Tenant ID. | Optional |

#### Context Output

There is no context output for this command.

### taegis-update-comment

***
Update an existing comment.

#### Base Command

`taegis-update-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Comment ID. | Required |
| comment | New comment text. | Required |

#### Context Output

There is no context output for this command.

### taegis-fetch-comment

***
Fetch a specific comment by ID.

#### Base Command

`taegis-fetch-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Comment ID. | Required |

#### Context Output

There is no context output for this command.

### taegis-add-evidence-to-investigation

***
Add evidence (alerts, events, or a CQL alert query) to an investigation. At least one of alerts, events, or alert_query is required.

#### Base Command

`taegis-add-evidence-to-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required |
| alerts | Comma-separated alert IDs to add as evidence. | Optional |
| events | Comma-separated event IDs to add as evidence. | Optional |
| alert_query | CQL query selecting alerts to add as evidence. | Optional |

#### Context Output

There is no context output for this command.

### taegis-create-investigation

***
Create a new investigation.

#### Base Command

`taegis-create-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | Investigation title. | Required |
| priority | Investigation priority (1-4). | Optional |
| status | Investigation status. Possible values are: OPEN, ACTIVE, AWAITING_ACTION, SUSPENDED, CLOSED_AUTHORIZED_ACTIVITY, CLOSED_CONFIRMED_SECURITY_INCIDENT, CLOSED_FALSE_POSITIVE_ALERT, CLOSED_INCONCLUSIVE, CLOSED_INFORMATIONAL, CLOSED_NOT_VULNERABLE, CLOSED_THREAT_MITIGATED. | Optional |
| alerts | Comma-separated alert IDs to associate with the new investigation. | Optional |
| key_findings | Key findings. | Optional |
| type | Investigation type. Possible values are: SECURITY_INVESTIGATION, INCIDENT_RESPONSE, THREAT_HUNT, MANAGED_XDR_THREAT_HUNT, CTU_THREAT_HUNT, MANAGED_XDR_ELITE_THREAT_HUNT, SECUREWORKS_INCIDENT_RESPONSE. | Optional |
| assignee_id | Assignee to set on the new investigation. Use @customer, @secureworks, auth0\|..., or a tenant user UUID. | Optional |
| tags | Comma-separated tags. | Optional |

#### Context Output

There is no context output for this command.

### taegis-create-sharelink

***
Create a ShareLink to an investigation, alert, or other Taegis object.

#### Base Command

`taegis-create-sharelink`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the investigation, alert, or other object to create a ShareLink for. | Required |
| type | Type of object the ShareLink points to. Possible values are: alertId, connectorId, connectionId, endpointDetails, eventId, investigationId, queryId, playbookTemplateId, playbookInstanceId, playbookExecutionId. | Required |
| tenant_id | Tenant ID. | Optional |

#### Context Output

There is no context output for this command.

### taegis-execute-playbook

***
Execute a Taegis playbook instance.

#### Base Command

`taegis-execute-playbook`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Playbook instance ID to execute. | Required |
| inputs | JSON object of optional playbook inputs. | Optional |

#### Context Output

There is no context output for this command.

### taegis-fetch-alerts

***
Fetch alerts by CQL query or by specific alert IDs.

#### Base Command

`taegis-fetch-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cql_query | CQL query selecting alerts. Ignored if ids is provided. | Optional |
| limit | Maximum number of alerts to return. | Optional |
| offset | Pagination offset. | Optional |
| ids | Comma-separated specific alert IDs to fetch (e.g. alert://id1,alert://id2). Overrides cql_query. | Optional |

#### Context Output

There is no context output for this command.

### taegis-fetch-assets

***
Search Taegis assets.

#### Base Command

`taegis-fetch-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number (0-based). | Optional |
| page_size | Number of assets to return per page. | Optional |
| endpoint_type | Filter by endpoint type. | Optional |
| host_id | Filter by host ID. | Optional |
| hostname | Filter by hostname. | Optional |
| investigation_id | Filter by investigation ID. | Optional |
| ip_address | Filter by IP address. | Optional |
| mac_address | Filter by MAC address. | Optional |
| os_family | Filter by OS family. | Optional |
| os_version | Filter by OS version. | Optional |
| sensor_version | Filter by sensor version. | Optional |
| username | Filter by username. | Optional |

#### Context Output

There is no context output for this command.

### taegis-fetch-endpoint

***
Fetch endpoint isolation status and health information for an asset.

#### Base Command

`taegis-fetch-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Asset/host ID. | Required |

#### Context Output

There is no context output for this command.

### taegis-fetch-investigation-alerts

***
Fetch alerts associated with an investigation.

#### Base Command

`taegis-fetch-investigation-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required |
| page | Page number (0-based). | Optional |
| page_size | Number of alerts to return per page. | Optional |

#### Context Output

There is no context output for this command.

### taegis-fetch-playbook-execution

***
Fetch a playbook execution by ID.

#### Base Command

`taegis-fetch-playbook-execution`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Playbook execution ID. | Required |

#### Context Output

There is no context output for this command.

### taegis-fetch-users

***
Fetch Taegis tenant users by ID or by search filters.

#### Base Command

`taegis-fetch-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Taegis user ID in 'auth0\|...' format. If provided, other filters are ignored. | Optional |
| email | Filter by email address. | Optional |
| status | Filter by user status. | Optional |
| page | Page number (0-based). | Optional |
| page_size | Number of users to return per page. | Optional |

#### Context Output

There is no context output for this command.

### taegis-isolate-asset

***
Isolate an asset/endpoint in Taegis.

#### Base Command

`taegis-isolate-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Asset ID to isolate. | Required |
| reason | Reason for isolating the asset. | Required |

#### Context Output

There is no context output for this command.

### taegis-update-alert-status

***
Update the resolution status of one or more alerts.

#### Base Command

`taegis-update-alert-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Comma-separated alert IDs. | Required |
| status | New resolution status for the alert(s). Possible values are: FALSE_POSITIVE, NOT_ACTIONABLE, OPEN, TRUE_POSITIVE_BENIGN, TRUE_POSITIVE_MALICIOUS, OTHER, SUPPRESSED. | Required |
| reason | Reason for the status change. | Optional |

#### Context Output

There is no context output for this command.

### taegis-archive-investigation

***
Archive an investigation.

#### Base Command

`taegis-archive-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required |

#### Context Output

There is no context output for this command.

### taegis-unarchive-investigation

***
Unarchive a previously archived investigation.

#### Base Command

`taegis-unarchive-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required |

#### Context Output

There is no context output for this command.

### taegis-update-investigation

***
Update an investigation.

#### Base Command

`taegis-update-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required |
| status | Investigation status. | Optional |
| priority | Investigation priority (1-4). | Optional |
| key_findings | Key findings. | Optional |
| tenant_id | Tenant ID. | Optional |

#### Context Output

There is no context output for this command.

### taegis-push-assignee-status

***
Push assignee and/or case status to Taegis. Run from an incident; use the form to select requested Assignee and Status, or leave blank to use current incident values. Refresh the incident to see the update reflected.

#### Base Command

`taegis-push-assignee-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID (optional; defaults to current incident dbotMirrorId). | Optional |
| tenant_id | Tenant ID (optional; from incident if not set). | Optional |
| assignee_id | Assignee to set in Taegis. Use @customer, @secureworks, or assignee display name (e.g. Sam Johnson). Optional when run from layout button; if omitted, uses current incident assignee. | Optional |
| status | Open status to set in Taegis (ACTIVE, AWAITING_ACTION, OPEN, SUSPENDED). Optional when run from layout button; if omitted, uses current incident status. Possible values are: ACTIVE, AWAITING_ACTION, OPEN, SUSPENDED. | Optional |

#### Context Output

There is no context output for this command.

### taegis-close-investigation

***
Close an investigation via closeInvestigation mutation.

#### Base Command

`taegis-close-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required |
| status | Close status (e.g. CLOSED_INCONCLUSIVE, CLOSED_INFORMATIONAL). | Required |
| reason | Close reason / notes (default Closed from Cortex XSOAR). | Optional |
| alerts_resolution_status | Alerts resolution status (e.g. TRUE_POSITIVE_BENIGN). | Optional |
| taegisxdrdetectionstatus | Taegis XDR detection status (same as alertsResolutionStatus; e.g. TRUE_POSITIVE_BENIGN). | Optional |
| tenant_id | Tenant ID. | Optional |

#### Context Output

There is no context output for this command.

### get-modified-remote-data

***
Get modified remote data for mirroring optimization (automatically called by Cortex XSOAR).

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Last update timestamp - automatically provided by Cortex XSOAR. | Optional |

#### Context Output

There is no context output for this command.

### get-remote-data

***
Get remote data for mirroring (automatically called by Cortex XSOAR).

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID (remoteId) - required for manual calls, automatically provided by Cortex XSOAR. | Optional |
| lastUpdate | Last update timestamp - automatically provided by Cortex XSOAR. | Optional |
| tenant_id | Tenant ID. | Optional |

#### Context Output

There is no context output for this command.

### update-remote-system

***
Update remote system for mirroring (automatically called by Cortex XSOAR).

#### Base Command

`update-remote-system`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### get-mapping-fields

***
Get mapping fields for schema selection (required for mappable integrations).

#### Base Command

`get-mapping-fields`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### taegis-update-remote-system

***
Manually test update remote system for mirroring.

#### Base Command

`taegis-update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| remoteId | Investigation ID (remoteId). | Required |
| data | Incident data changes (JSON format). | Optional |
| tenant_id | Tenant ID. | Optional |

#### Context Output

There is no context output for this command.

### taegis-get-remote-data

***
Manually test get remote data for mirroring.

#### Base Command

`taegis-get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required |
| tenant_id | Tenant ID. | Optional |

#### Context Output

There is no context output for this command.

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Taegis XDR v3 corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Taegis XDR v3 events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Taegis XDR v3 events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and Taegis XDR v3 events will be reflected in both directions. |

3. Optional: You can go to the mirroring tags parameter and select the tags used to mark incident entries to be mirrored. Available tags are: Comment Entry Tag To Taegis.
4. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in Taegis XDR v3.
5. Optional: Check the *Close Mirrored Taegis XDR v3 event* integration parameter to close them when the corresponding Cortex XSOAR incident is closed.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Taegis XDR v3.
