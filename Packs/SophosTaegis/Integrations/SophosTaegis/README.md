For integration with the Secureworks Taegis XDR platform.

## Configure Taegis XDR in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Client ID |  | True |
| Client Secret |  | True |
| API base URL | Taegis API base URL for your environment. Do not include a trailing slash. Required for all commands. | False |
| XDR base URL | Taegis XDR \(UI\) base URL for your environment. Used for investigation/alert links. Do not include a trailing slash. Required for all commands. | False |
| Tenant ID |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Maximum number of incidents per fetch | The maximum limit is 200. | False |
| Incidents Fetch Interval | The interval in minutes to fetch incidents. The default is 1 minute. | False |
| First fetch timestamp |  | False |
| Fetch Incident Type | The type of incidents to fetch. The default is investigations. | False |
| Include Assets in Fetch |  | False |
| Fetch investigations - exclusion list (assignee emails or names) | EXCLUSION LIST: Comma-separated assignee emails, display names, or assignee IDs \(e.g. user@domain.com, Sophos, auth0\|xxx\). Investigations assigned to any matching assignee are EXCLUDED \(no XSOAR incident\). Match is by email, name, or assignee_id. If a team name \(e.g. Sophos\) does not match, check debug logs for assignee_id and add that ID to this list. Leave empty to fetch all. | False |
| Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from Taegis XDR to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to Taegis XDR\), or Incoming And Outgoing \(bidirectional\). | False |
| Comment Entry Tag To Taegis | Choose the tag to add to an entry to mirror it as a comment in Taegis XDR. | False |
| Comment Entry Tag From Taegis | Choose the tag to add to an entry to mirror it as a comment from Taegis XDR. | False |
| Close XSOAR incident when Taegis investigation is closed | When enabled, closing a Taegis investigation \(status starting with CLOSED_\) will close the mirrored incident in Cortex XSOAR. | False |
| Use closeInvestigation when Taegis XDR Case Status is set to closed | When enabled, setting Taegis XDR Case Status \(taegisxdrcasestatus\) to a closed value \(e.g. CLOSED_INCONCLUSIVE\) will close the investigation in Taegis via the closeInvestigation mutation \(with reason\). XSOAR incident status is not used to close Taegis. | False |
| How many investigations to mirror incoming each time | If a greater number of investigations than the limit were modified, then they won't all be mirrored in a single run. | False |
| Timestamp field to query for updates as part of the mirroring flow | Field used to determine when an investigation was last updated for mirroring. Default is updated_at. The investigationsSearch GraphQL API uses the Investigation type with snake_case \(updated_at\). Taegis v2 docs may show updatedAt for investigationV2/investigationsV2; use updated_at for investigationsSearch. | False |
| XSOAR Taegis XDR Key Findings is master | When enabled, XSOAR "Taegis XDR Key Findings" \(taegisxdrkeyfindings\) is always pushed to Taegis Key Findings on every update \(XSOAR is master\). When disabled \(default\), Key Findings are only pushed when the user explicitly changes that field in XSOAR, so Taegis edits are not overwritten \(bidirectional-friendly\). | False |
| Assign case to Sophos MDR team after comment | When enabled, the "Assign case to Sophos MDR team" field in the Add Comment form defaults to "Yes". When disabled \(default\), the field defaults to "No". Users can still override per comment to "Yes" or "No". | False |
| Archive Taegis XDR case on close | When enabled, the "Taegis XDR Archive on Close" checkbox defaults to checked in the Close Incident panel. When disabled \(default\), the checkbox is unchecked. Archiving removes the case from the active Taegis XDR case list. Users can override this per incident at close time. | False |
| Allow reopen of archived Taegis XDR cases | When enabled, reopening a closed XSOAR incident will automatically unarchive the associated Taegis XDR case before setting it back to ACTIVE. When disabled \(default\), archived cases cannot be reopened via XSOAR; the case must be unarchived manually in Taegis XDR first. | False |
| Retry on Taegis API rate limit (429) | When enabled, GraphQL and auth requests that receive HTTP 429 \(rate limit\) are retried with backoff. Helps when closing many mirrored incidents at once. Uses Retry-After when Taegis returns it. | False |
| Max retries on API rate limit | Retry attempts after a 429 \(in addition to the first request\). Range 0-10. Each wait uses Retry-After or exponential backoff. | False |
| Base delay (seconds) for rate-limit backoff | When Retry-After is absent, wait base x 2^attempt seconds before each retry \(capped per wait\). | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### taegis-fetch-investigation

***
Fetch a specific investigation or list of investigations

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
Fetch comments by Investigation ID

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
Create a comment on an investigation

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
### taegis-update-investigation

***
Update an investigation

#### Base Command

`taegis-update-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required | 
| status | Investigation status. | Optional | 
| priority | Investigation priority (1-4). | Optional | 
| keyFindings | Key findings. | Optional | 
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
| assignee_id | Assignee to set in Taegis. Use @customer, @secureworks, @sophos, or assignee display name (e.g. Sam Johnson). Optional when run from layout button; if omitted, uses current incident assignee. | Optional | 
| status | Open status to set in Taegis (ACTIVE, AWAITING_ACTION, OPEN, SUSPENDED). Optional when run from layout button; if omitted, uses current incident status. Possible values are: ACTIVE, AWAITING_ACTION, OPEN, SUSPENDED. | Optional | 

#### Context Output

There is no context output for this command.
### taegis-close-investigation

***
Close an investigation via closeInvestigation mutation

#### Base Command

`taegis-close-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID. | Required | 
| status | Close status (e.g. CLOSED_INCONCLUSIVE, CLOSED_INFORMATIONAL). | Required | 
| reason | Close reason / notes (default Closed from Cortex XSOAR). | Optional | 
| alertsResolutionStatus | Alerts resolution status (e.g. TRUE_POSITIVE_BENIGN). | Optional | 
| taegisxdrdetectionstatus | Taegis XDR detection status (same as alertsResolutionStatus; e.g. TRUE_POSITIVE_BENIGN). | Optional | 
| tenant_id | Tenant ID. | Optional | 

#### Context Output

There is no context output for this command.
### get-modified-remote-data

***
Get modified remote data for mirroring optimization (automatically called by XSOAR)

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Last update timestamp - automatically provided by XSOAR. | Optional | 

#### Context Output

There is no context output for this command.
### get-remote-data

***
Get remote data for mirroring (automatically called by XSOAR)

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID (remoteId) - required for manual calls, automatically provided by XSOAR. | Optional | 
| lastUpdate | Last update timestamp - automatically provided by XSOAR. | Optional | 
| tenant_id | Tenant ID. | Optional | 

#### Context Output

There is no context output for this command.
### update-remote-system

***
Update remote system for mirroring (automatically called by XSOAR)

#### Base Command

`update-remote-system`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### get-mapping-fields

***
Get mapping fields for schema selection (required for mappable integrations)

#### Base Command

`get-mapping-fields`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### taegis-update-remote-system

***
Manually test update remote system for mirroring

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
Manually test get remote data for mirroring

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

You can enable incident mirroring between Cortex XSOAR incidents and Taegis XDR corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Taegis XDR events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Taegis XDR events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and Taegis XDR events will be reflected in both directions. |

3. Optional: You can go to the mirroring tags parameter and select the tags used to mark incident entries to be mirrored. Available tags are: Comment Entry Tag To Taegis.
4. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in Taegis XDR.
5. Optional: Check the *Close Mirrored Taegis XDR event* integration parameter to close them when the corresponding Cortex XSOAR incident is closed.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Taegis XDR.
