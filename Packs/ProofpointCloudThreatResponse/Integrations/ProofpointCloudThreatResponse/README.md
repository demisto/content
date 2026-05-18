Fetches Proofpoint Cloud Threat Response (CTR) incidents into Cortex XSOAR for case management, and exposes commands to list and retrieve incident details.
This integration was integrated and tested with version xx of Proofpoint Cloud Threat Response.

## Configure Proofpoint Cloud Threat Response in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The base URL of the Proofpoint Cloud Threat Response API. | True |
| Client ID | The Client ID and Client Secret generated from your Proofpoint Threat Response account \(API Key Management\). | True |
| Client Secret |  | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Maximum number of incidents per fetch | The maximum number of incidents to fetch each interval. Default and maximum is 200. | False |
| Fetch delta (minutes) | An additional buffer \(in minutes\) subtracted from the start of each fetch window to mitigate clock drift and ensure no incidents are missed. | False |
| Fetch incidents with specific states | Must be set when fetch is enabled. Selecting both \`open_incidents\` and \`closed_incidents\` returns an empty result from the upstream API. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### proofpoint-ctr-incidents-list

***
Returns a list of Proofpoint Cloud Threat Response incidents matching the supplied filters.

#### Base Command

`proofpoint-ctr-incidents-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The start of the time range filter. Accepts a free text date (e.g., `3 days`, `2024-11-26T16:18:07Z`). | Optional |
| end_time | The end of the time range filter. Accepts a free text date. Defaults to now when omitted. | Optional |
| incident_id_filters | A comma-separated list of incident `displayId` values (numeric). For example, `781,782`. | Optional |
| source_filters | Filter incidents by source. Possible values are: abuse_mailbox, tap, smart_search, message_csv_upload. | Optional |
| other_filters | Filter incidents by state or VAP. Selecting both `open_incidents` and `closed_incidents` returns an empty result from the upstream API. Possible values are: open_incidents, closed_incidents, vap. | Optional |
| verdict_filters | Filter incidents by verdict. Possible values are: verdict_failed, verdict_low_risk, verdict_manual_review, verdict_threat. | Optional |
| disposition | Filter incidents by disposition. Possible values are: bulk, clean, impostor, in_progress, internal, low_risk, malware, manual_review, not_set, phish, scam, simulated_phish, spam, suspicious, tap_false_positive, toad, vendor. | Optional |
| confidence_filters | Filter incidents by confidence level. Possible values are: confidence_high, confidence_medium, confidence_low. | Optional |
| limit | The maximum number of incidents to return. Default is 50. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofPointCloud.Incident.id | String | The internal UUID of the incident. |
| ProofPointCloud.Incident.displayId | Number | The numeric display ID of the incident. |
| ProofPointCloud.Incident.title | String | The incident title. |
| ProofPointCloud.Incident.state | String | The state of the incident \(open/closed\). |
| ProofPointCloud.Incident.createdAt | Date | The creation timestamp of the incident. |
| ProofPointCloud.Incident.updatedAt | Date | The last update timestamp of the incident. |
| ProofPointCloud.Incident.messageCount | Number | The number of messages associated with the incident. |
| ProofPointCloud.Incident.assignedTeamName | String | The name of the team the incident is assigned to. |
| ProofPointCloud.Incident.sourceTypes | Unknown | The list of source types that produced the incident. |
| ProofPointCloud.Incident.dispositions | Unknown | The list of dispositions assigned to the incident. |
| ProofPointCloud.Incident.clearConfidences | Unknown | The list of confidence values for the incident. |
| ProofPointCloud.Incident.sourcesData | Unknown | The raw sources data array for the incident. |

### proofpoint-ctr-incident-get

***
Returns full details for a specific Proofpoint Cloud Threat Response incident.

#### Base Command

`proofpoint-ctr-incident-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | A comma-separated list of incident UUIDs (e.g., `440def43-c322-42ba-a6d6-a2306128ea3b`). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofPointCloud.Incident.summary.id | String | The internal UUID of the incident. |
| ProofPointCloud.Incident.summary.displayId | Number | The numeric display ID of the incident. |
| ProofPointCloud.Incident.summary.title | String | The incident title. |
| ProofPointCloud.Incident.summary.state | String | The state of the incident. |
| ProofPointCloud.Incident.summary.createdAt | Date | The creation timestamp of the incident. |
| ProofPointCloud.Incident.summary.updatedAt | Date | The last update timestamp of the incident. |
| ProofPointCloud.Incident.summary.priority | String | The priority of the incident. |
| ProofPointCloud.Incident.summary.messageCount | Number | The number of messages associated with the incident. |
| ProofPointCloud.Incident.summary.assignedTeamName | String | The name of the team the incident is assigned to. |
| ProofPointCloud.Incident.summary.assignedApplicationUserName | String | The user the incident is assigned to. |
| ProofPointCloud.Incident.activities | Unknown | The activities associated with the incident. |
