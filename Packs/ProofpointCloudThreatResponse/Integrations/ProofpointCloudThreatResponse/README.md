Fetches Proofpoint Cloud Threat Response (CTR) incidents into Cortex XSOAR for case management, and exposes commands to list and retrieve incident details.
This integration was integrated and tested with version 1.0 of Proofpoint Cloud Threat Response.

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
| limit | The maximum number of incidents to return. Default is 50. | Optional |

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
| ProofPointCloud.Incident.priority | String | The priority of the incident. |
| ProofPointCloud.Incident.closedAt | Date | The timestamp when the incident was closed, if applicable. |
| ProofPointCloud.Incident.assignedUserName | String | The username of the individual the incident is assigned to. |
| ProofPointCloud.Incident.sourceTypes | Array | The list of source types that produced the incident. |
| ProofPointCloud.Incident.dispositions | Array | The list of dispositions assigned to the incident. |
| ProofPointCloud.Incident.clearVerdicts | Array | The list of clear verdicts for the incident. |
| ProofPointCloud.Incident.clearConfidences | Array | The list of confidence values for the incident. |
| ProofPointCloud.Incident.sourcesData | Array | The raw sources data array for the incident. |

#### Command Example

```!proofpoint-ctr-incidents-list limit=2```

#### Context Example

```json
[
    {
        "id": "00000000-0000-0000-0000-000000000001",
        "createdAt": "2024-01-01T10:00:00.000+00:00",
        "updatedAt": "2024-01-01T10:05:00.000+00:00",
        "displayId": 12345,
        "priority": "high",
        "title": "user[@]example[.]com reported a message \"Suspicious phishing attempt\"",
        "state": "open",
        "assignedTeamName": "SOC_Analyst",
        "messageCount": 1,
        "sourceTypes": ["abuse_mailbox"],
        "sourcesData": [{"type": "AbuseMailbox", "name": "Proofpoint CLEAR"}],
        "dispositions": ["manual_review"],
        "clearVerdicts": ["manual_review"],
        "clearConfidences": ["low"]
    },
    {
        "id": "00000000-0000-0000-0000-000000000002",
        "createdAt": "2024-01-01T09:00:00.000+00:00",
        "updatedAt": "2024-01-01T09:30:00.000+00:00",
        "closedAt": "2024-01-01T09:30:00.000+00:00",
        "displayId": 12344,
        "priority": null,
        "title": "other[@]example[.]com reported a message \"Low risk email review\"",
        "state": "closed",
        "assignedTeamName": "SOC_Analyst",
        "messageCount": 18,
        "sourceTypes": ["abuse_mailbox"],
        "sourcesData": [{"type": "AbuseMailbox", "name": "Proofpoint CLEAR"}],
        "dispositions": ["low_risk"],
        "clearVerdicts": ["low_risk"],
        "clearConfidences": ["high"]
    }
]
```

#### Human Readable Output

>### Proofpoint Cloud Threat Response Incidents
>
>| ID | Created At | Type | State | Message Count | Assigned Team Name | Title | Source Types |
>|---|---|---|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000001 | 2024-01-01T10:00:00.000+00:00 | AbuseMailbox | open | 1 | SOC_Analyst | user[@]example[.]com reported a message "Suspicious phishing attempt" | abuse_mailbox |
>| 00000000-0000-0000-0000-000000000002 | 2024-01-01T09:00:00.000+00:00 | AbuseMailbox | closed | 18 | SOC_Analyst | other[@]example[.]com reported a message "Low risk email review" | abuse_mailbox |

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
| ProofPointCloud.Incident.summary.closedAt | Date | The timestamp when the incident was closed, if applicable. |
| ProofPointCloud.Incident.summary.openedAt | Date | The timestamp when the incident was opened. |
| ProofPointCloud.Incident.summary.messageSourceData | Unknown | Breakdown of message sources \(TAP, abuse mailbox, smart search, etc.\) for the incident. |
| ProofPointCloud.Incident.comments | Array | The comments associated with the incident. |
| ProofPointCloud.Incident.activities | Array | The activities associated with the incident. |

#### Command Example

```!proofpoint-ctr-incident-get incident_id=00000000-0000-0000-0000-000000000001```

#### Context Example

```json
{
    "summary": {
        "id": "00000000-0000-0000-0000-000000000001",
        "createdAt": "2024-01-01T10:00:00.000+00:00",
        "updatedAt": "2024-01-01T10:05:00.000+00:00",
        "displayId": 12345,
        "priority": "high",
        "state": "open",
        "title": "user[@]example[.]com reported a message \"Suspicious phishing attempt\"",
        "closedAt": null,
        "openedAt": "2024-01-01T10:00:00.000+00:00",
        "assignedTeamName": "SOC_Analyst",
        "assignedApplicationUserName": null,
        "messageCount": 1,
        "messageSourceData": {
            "hasTapAlert": false,
            "hasAbuseAlert": true,
            "hasSmartSearchImport": false,
            "hasMessageCsvUpload": false,
            "hasWorkbenchEvent": false,
            "hasImdAlert": false,
            "hasMailBombAlert": false
        }
    },
    "comments": [],
    "activities": [
        {
            "id": "00000000-0000-0000-0000-000000000006",
            "cause_type": "system",
            "created_at": "2024-01-01T10:00:00.000",
            "occurred_at": "2024-01-01T10:00:00.000000",
            "activity_type": "incident_creation",
            "activity_details": {
                "source_name": "Proofpoint CLEAR",
                "initial_priority": null,
                "initial_team_name": "SOC_Analyst"
            },
            "causing_user_name": null,
            "causing_workflow_name": null
        },
        {
            "id": "00000000-0000-0000-0000-000000000008",
            "cause_type": "history",
            "created_at": "2024-01-01T10:00:10.000",
            "activity_type": "quarantine",
            "activity_details": {
                "quarantine_attempts": [
                    {
                        "state": "complete",
                        "disposition": "message_moved"
                    }
                ]
            },
            "causing_workflow_name": "Official Manual Review"
        }
    ]
}
```

#### Human Readable Output

>### Proofpoint Cloud Threat Response Incident: 12345
>
>| ID | Created At | State | Message Count | Assigned Team Name | Title |
>|---|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000001 | 2024-01-01T10:00:00.000+00:00 | open | 1 | SOC_Analyst | user[@]example[.]com reported a message "Suspicious phishing attempt" |
