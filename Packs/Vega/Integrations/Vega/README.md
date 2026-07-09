Vega integration for fetching alerts and incidents from the Vega platform.
This integration was integrated and tested with version xx of Vega.

## Prerequisites

To connect to the Vega platform, you need an **Access Key ID** and an **Access Key**.

1. Log in to your Vega console.
2. Navigate to **Settings** > **Machine Users** / **API Keys**.
3. Generate or retrieve an **Access Key ID** and **Access Key** for your machine user.
4. Copy the **Access Key ID** and **Access Key** and paste them into the respective configuration parameters of this integration.

## Configure Vega in Cortex XSOAR


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL | The Base URL of the Vega API. | True |
| Access Key ID | The Access Key ID used to authenticate with the Vega API. | True |
| Access Key | The Access Key used to authenticate with the Vega API. | True |
| Fetch incidents |  | False |
| Incidents Fetch Interval |  | True |
| Maximum incidents per fetch | Maximum number of Vega alerts and incidents to fetch per cycle, combined. Valid range is 1-50. Invalid values default to 50 during fetch. | True |
| Fetch Lookback (minutes) | On each fetch cycle, the query window is shifted backwards by this many minutes to catch alerts and incidents that were indexed late on the Vega side. Deduplication prevents re-ingestion. Valid range is 1-60. | True |
| Vega Entities to fetch | Select the Vega entities to fetch as XSOAR incidents. | True |
| Backfill Days | Number of days before today to fetch alerts and incidents on the first run. Use 0 for today only. Valid range is 0–365. | True |
| Enable XSOAR to Vega mirroring | When enabled, changes made in Cortex XSOAR investigations are mirrored to Vega for status, verdict, verdict reasoning, severity, and comments. Requires the Vega Outgoing Mapper on this instance. When disabled, Vega to XSOAR mirroring remains enabled. | False |
| Outgoing fields to mirror | Select which investigation fields are mirrored from Cortex XSOAR to Vega when outgoing mirroring is enabled. If empty, all fields are mirrored. War Room comments are included when Comments is selected. Any custom values entered outside the available options are ignored. | False |
| Alert Severities to fetch | Filter alerts by severity. If empty, all severities are fetched. Any custom values entered outside the available options are ignored and will not affect the fetch cycle. | False |
| Alert Statuses to fetch | Filter alerts by status. If empty, all statuses are fetched. Any custom values entered outside the available options are ignored and will not affect the fetch cycle. | False |
| Alert Verdicts to fetch | Filter alerts by verdict. If empty, all verdicts are fetched. Any custom values entered outside the available options are ignored and will not affect the fetch cycle. | False |
| Incident Severities to fetch | Filter incidents by severity. If empty, all severities are fetched. Any custom values entered outside the available options are ignored and will not affect the fetch cycle. | False |
| Incident Statuses to fetch | Filter incidents by status. If empty, all statuses are fetched. Any custom values entered outside the available options are ignored and will not affect the fetch cycle. | False |
| Incident Verdicts to fetch | Filter incidents by verdict. If empty, all verdicts are fetched. Any custom values entered outside the available options are ignored and will not affect the fetch cycle. | False |
| Has related incidents | Filter alerts by whether they have related incidents. Select Yes to fetch alerts with related incidents, No to fetch alerts without related incidents, or both to fetch all alerts. At least one option must be selected. | True |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### vega-get-alert-events

***
Fetch all aggregated alert events for a Vega alert using internal API pagination, then return the requested display page as a markdown table and CustomFields for the Alert Events layout section.

#### Base Command

`vega-get-alert-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Vega alert API id (UUID). When omitted, resolves the alert id from the current Vega Alert incident. | Optional | 
| limit | Number of alert events to display per page. Also used as the Vega API batch size when fetching all events. Default is 200. | Optional | 
| offset | Pagination offset for alert events. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vega.AlertEvents.AlertId | String | Vega alert ID. | 
| Vega.AlertEvents.Total | Number | Total number of alert events reported by Vega. | 
| Vega.AlertEvents.Offset | Number | Pagination offset used for the current page. | 
| Vega.AlertEvents.Limit | Number | Page size used for the current fetch. | 
| Vega.AlertEvents.Count | Number | Number of alert events returned in the current page. | 
| Vega.AlertEvents.HasAlertEvents | Boolean | Whether the alert returned real alert events instead of aggregated parse-field summary rows. | 
| Vega.AlertEvents.Cached | Boolean | Whether the response was served from cached incident data. | 
| Vega.AlertEvents.CustomFields | Unknown | Incident custom fields to persist for the Alert Events layout section. | 

### vega-set-detections-state

***
Set the state for one or more Vega detections.

#### Base Command

`vega-set-detections-state`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | One or more Vega detection IDs to update. | Required | 
| state | Target detection state. Possible values are: ENABLED, DISABLED, TEST_MODE. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vega.DetectionsState.State | String | The state applied to the detections. | 
| Vega.DetectionsState.IDs | String | Detection IDs updated by Vega. | 
| Vega.DetectionsState.Count | Number | Number of detection IDs updated. | 

### vega-update-detections

***
Update severity, status, state, and/or tags for one or more Vega detections using the updateDetections GraphQL mutation.

#### Base Command

`vega-update-detections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | One or more Vega detection IDs to update. | Required | 
| severity | Target Vega detection severity. Possible values are: LOW, MEDIUM, HIGH, CRITICAL. | Optional | 
| state | Target Vega detection state. Possible values are: ENABLED, DISABLED, TEST_MODE. | Optional | 
| tags | Tags to apply to the Vega detection. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vega.Detection.ID | String | Updated Vega detection ID. | 
| Vega.Detection.Name | String | Updated Vega detection name. | 
| Vega.Detection.Severity | String | Updated Vega detection severity. | 
| Vega.Detection.Status | String | Updated Vega detection status. | 
| Vega.Detection.State | String | Updated Vega detection state. | 
| Vega.Detection.Tags | String | Updated Vega detection tags. | 
| Vega.Detection.ValidationStatus | String | Vega validation status for the detection update. | 

### vega-update-alert

***
Immediately update Vega alert status, severity, verdict, verdict reasoning, assignees, and/or comment on the Vega platform and sync the open XSOAR investigation when run from a Vega Alert investigation.

#### Base Command

`vega-update-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | One or more Vega alert IDs to update. Accepts a comma-separated list or repeated values (for example, alert_ids=alert-1,alert-2). Use this to update alerts directly from the war room without opening an investigation. When omitted, the alert ID is resolved from the current Vega Alert investigation. | Optional | 
| status | Target Vega alert status. Possible values are: OPEN, IN PROGRESS, PEER REVIEW, RESOLVED. | Optional | 
| verdict | Target Vega alert verdict. Possible values are: MALICIOUS, SUSPICIOUS, BENIGN, INCONCLUSIVE, NA. | Optional | 
| severity | Target Vega alert severity. Possible values are: LOW, MEDIUM, HIGH, CRITICAL. | Optional | 
| verdict_reasoning | Target Vega alert verdict reasoning. | Optional | 
| comment | Comment to add on the Vega alert. | Optional | 
| assignees | One or more Vega user IDs to assign to the alert. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vega.Alert.id | String | Updated Vega alert ID. | 
| Vega.Alert.status | String | Updated Vega alert status. | 
| Vega.Alert.severity | String | Updated Vega alert severity. | 
| Vega.Alert.verdict | String | Updated Vega alert verdict. | 
| Vega.Alert.assignee | String | Updated Vega alert assignee email, display name, or user ID. | 

### vega-update-incident

***
Immediately update Vega incident status, verdict, verdict reasoning, severity, assignee emails, and/or comment on the Vega platform and sync the open XSOAR investigation when run from a Vega Incident investigation.

#### Base Command

`vega-update-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_ids | One or more Vega incident IDs to update. Accepts a comma-separated list or repeated values (for example, incident_ids=inc-1,inc-2). Use this to update incidents directly from the war room without opening an investigation. When omitted, the incident ID is resolved from the current Vega Incident investigation. | Optional | 
| status | Target Vega incident status. Possible values are: NEW, INVESTIGATING, ON HOLD, EXTERNAL ESCALATION, RESOLVED, REOPENED, REVIEW RECOMMENDED, RESPONSE REQUIRED, UNDER REVIEW. | Optional | 
| verdict | Target Vega incident verdict. Possible values are: MALICIOUS, SUSPICIOUS, BENIGN, INCONCLUSIVE, NA. | Optional | 
| severity | Target Vega incident severity. Possible values are: LOW, MEDIUM, HIGH, CRITICAL. | Optional | 
| verdict_reasoning | Target Vega incident verdict reasoning. | Optional | 
| comment | Comment to add on the Vega incident. | Optional | 
| assignee_emails | One or more email addresses to assign to the Vega incident. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vega.Incident.id | String | Updated Vega incident ID. | 
| Vega.Incident.status | String | Updated Vega incident status. | 
| Vega.Incident.verdict | String | Updated Vega incident verdict. | 
| Vega.Incident.severity | String | Updated Vega incident severity. | 
| Vega.Incident.assignee | String | Updated Vega incident assignee email, display name, or user ID. | 

### get-remote-data

***
Gets remote data from a remote Vega alert or incident. Used for debugging incoming mirroring.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote Vega alert or incident ID. | Required | 
| lastUpdate | UTC timestamp in seconds. The incident is only updated if it was modified after the last update time. | Optional | 

#### Context Output

There is no context output for this command.
### get-modified-remote-data

***
Gets Vega alert and incident IDs modified since the last update time. Used for debugging incoming mirroring.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | UTC timestamp in seconds. Returns Vega alert and incident IDs updated since this time. | Required | 

#### Context Output

There is no context output for this command.
### update-remote-system

***
Pushes Cortex XSOAR investigation changes to Vega when outgoing mirroring is enabled.

#### Base Command

`update-remote-system`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### get-mapping-fields

***
Returns the outgoing mirroring fields for Vega Alert and Vega Incident investigations.

#### Base Command

`get-mapping-fields`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Vega corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Vega.
