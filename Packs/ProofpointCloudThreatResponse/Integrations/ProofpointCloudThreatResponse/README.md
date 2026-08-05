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
| Enrich incidents during fetch | When enabled, each fetched incident is enriched with full details \(activities, comments, message source data\) by calling the GET /incidents/\{id\} endpoint once per incident. Disable when fetching large volumes to avoid rate limits. | False |
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
| priority_filters | A comma-separated list of priority levels to filter incidents by. Possible values are: high, medium, low. | Optional |
| sort | Sort order for results by creation time. Possible values are: asc, desc. Default is desc. | Optional |
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
| ProofPointCloud.Incident.sourceTypes | Array | The list of source types that produced the incident. |
| ProofPointCloud.Incident.dispositions | Array | The list of dispositions assigned to the incident. |
| ProofPointCloud.Incident.clearConfidences | Array | The list of confidence values for the incident. |
| ProofPointCloud.Incident.priority | String | The priority of the incident. |
| ProofPointCloud.Incident.closedAt | Date | The timestamp when the incident was closed, if applicable. |
| ProofPointCloud.Incident.assignedUserName | String | The username of the individual the incident is assigned to. |
| ProofPointCloud.Incident.clearVerdicts | Array | The list of clear verdicts for the incident. |
| ProofPointCloud.Incident.sourcesData | Array | The raw sources data array for the incident. |

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
| ProofPointCloud.Incident.id | String | The internal UUID of the incident. |
| ProofPointCloud.Incident.displayId | Number | The numeric display ID of the incident. |
| ProofPointCloud.Incident.title | String | The incident title. |
| ProofPointCloud.Incident.state | String | The state of the incident. |
| ProofPointCloud.Incident.createdAt | Date | The creation timestamp of the incident. |
| ProofPointCloud.Incident.updatedAt | Date | The last update timestamp of the incident. |
| ProofPointCloud.Incident.priority | String | The priority of the incident. |
| ProofPointCloud.Incident.messageCount | Number | The number of messages associated with the incident. |
| ProofPointCloud.Incident.assignedTeamName | String | The name of the team the incident is assigned to. |
| ProofPointCloud.Incident.assignedApplicationUserName | String | The user the incident is assigned to. |
| ProofPointCloud.Incident.closedAt | Date | The timestamp when the incident was closed, if applicable. |
| ProofPointCloud.Incident.openedAt | Date | The timestamp when the incident was opened. |
| ProofPointCloud.Incident.messageSourceData | Unknown | Breakdown of message sources \(TAP, abuse mailbox, smart search, etc.\) for the incident. |
| ProofPointCloud.Incident.comments | Array | The comments associated with the incident. |
| ProofPointCloud.Incident.activities | Array | The activities associated with the incident. |

#### Command Example

```!proofpoint-ctr-incident-get incident_id=00000000-0000-0000-0000-000000000001```

#### Context Example

```json
{
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

## Known Limitations

### Fetch Enrichment and API Rate Limits

By default, the **"Enrich incidents during fetch"** parameter is disabled. When disabled, each fetch cycle makes a single API call to retrieve the incident list, and the raw JSON stored per incident contains only the fields returned by the list endpoint (summary fields such as `id`, `title`, `state`, `createdAt`, `messageCount`, etc.).

When enrichment is enabled, the integration makes one additional `GET /api/v1/tric/incidents/{id}` call **per incident** in every fetch cycle. This provides richer data immediately (activities, comments, `messageSourceData`) but multiplies API call volume proportionally to the number of incidents fetched. In environments with high incident volume this can trigger Proofpoint API rate limits (HTTP 429).

**Recommended approach for high-volume environments:**

1. Keep **"Enrich incidents during fetch"** disabled (default).
2. Use the `proofpoint-ctr-incident-get` command to enrich individual incidents on demand from a playbook or manually from the War Room.
3. Because both commands write to the same context key (`ProofPointCloud.Incident.id`), running `proofpoint-ctr-incident-get` after `proofpoint-ctr-incidents-list` will **enrich the existing context entry** rather than creating a duplicate.

### proofpoint-ctr-safelist-remove-entry

***
Removes an entry from the organizational Safe List.

#### Base Command

`proofpoint-ctr-safelist-remove-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The PPS Cluster ID. | Required |
| attribute | The attribute of the entry to remove. Possible values are: from, hfrom, ip, host, helo, rcpt. | Required |
| operator | The operator of the entry to remove. Possible values are: equal, contain, is_in_list. | Required |
| value | The value for the entry. | Required |

#### Context Output

There is no context output for this command.

### proofpoint-ctr-safelist-add-entry

***
Adds an entry to the organizational Safe List.

#### Base Command

`proofpoint-ctr-safelist-add-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The PPS Cluster ID. | Required |
| attribute | The attribute to filter on. Possible values are: from, hfrom, ip, host, helo, rcpt. | Required |
| operator | The operator to use. Possible values are: equal, contain, is_in_list. | Required |
| value | The value for the entry. | Required |
| comment | An optional comment for the entry. | Optional |

#### Context Output

There is no context output for this command.

### proofpoint-ctr-message-list

***
Retrieves a single Proofpoint Cloud Threat Response message by its UUID, or a filtered list of messages.

#### Base Command

`proofpoint-ctr-message-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The UUID of a single message to retrieve. | Optional |
| rfc_message_id | A comma-separated list of RFC Message IDs to search for. | Optional |
| recipient_address | A comma-separated list of recipient email addresses to filter by. | Optional |
| sender_address | A comma-separated list of sender email addresses to filter by. | Optional |
| subject | A substring to search for in the message subject. | Optional |
| start_time | The start of the time range filter. Accepts a free text date (e.g., `2 hours`, `2024-11-26T16:18:07Z`). | Optional |
| end_time | The end of the time range filter. Accepts a free text date. Defaults to now when omitted. | Optional |
| source_filters | A comma-separated list of sources to filter by. Possible values are: abuse_mailbox, tap, smart_search, message_csv_upload, mail_bomb. | Optional |
| status_filters | A comma-separated list of message statuses to filter by. Possible values are: message_delivered, message_unread, message_read, permitted_click. | Optional |
| quarantine_filters | A comma-separated list of remediation statuses to filter by. | Optional |
| disposition_filters | A comma-separated list of dispositions to filter by. Possible values are: bulk, clean, impostor, in_progress, internal, low_risk, malware, manual_review, not_set, phish, scam, simulated_phish, spam, suspicious, tap_false_positive, toad, vendor. | Optional |
| confidence_filters | A comma-separated list of CLEAR confidence levels to filter by. Possible values are: confidence_high, confidence_medium, confidence_low. | Optional |
| verdict_filters | A comma-separated list of CLEAR verdicts to filter by. Possible values are: verdict_failed, verdict_low_risk, verdict_manual_review, verdict_threat. | Optional |
| tap_threat_id | A comma-separated list of TAP Threat IDs to filter by. | Optional |
| tap_threat_type_filters | A comma-separated list of TAP threat types to filter by. Possible values are: tap_threat_type_delivered_attachment_threat, tap_threat_type_delivered_message_threat, tap_threat_type_delivered_url_threat, tap_threat_type_unprotected_url_threat. | Optional |
| limit | The maximum number of messages to return. Default is 50. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofPointCloud.Message.id | String | The message UUID. |
| ProofPointCloud.Message.email_subject | String | The message subject. |
| ProofPointCloud.Message.sender_address | String | The message sender address. |
| ProofPointCloud.Message.recipient_address | String | The message recipient address. |
| ProofPointCloud.Message.received_at | Date | The timestamp the message was received. |
| ProofPointCloud.Message.disposition | String | The message disposition. |
| ProofPointCloud.Message.remediation_status | String | The message remediation status. |

### proofpoint-ctr-workflows-list

***
Returns a list of Proofpoint Cloud Threat Response manual workflows.

#### Base Command

`proofpoint-ctr-workflows-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enabled | If true, returns only enabled manual workflows. Possible values are: true, false. | Optional |
| type | Filter workflows by type. Possible values are: incident, message. | Optional |
| limit | The maximum number of workflows to return. Default is 50. Default is 50. | Optional |
| all_results | If true, ignore the limit and return all workflows. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofPointCloud.Workflow.id | String | The workflow ID. |
| ProofPointCloud.Workflow.name | String | The workflow name. |
| ProofPointCloud.Workflow.enabled | Boolean | Whether the workflow is enabled. |
| ProofPointCloud.Workflow.type | String | The workflow type. |
| ProofPointCloud.Workflow.createdAt | Date | The workflow creation timestamp. |

### proofpoint-ctr-safelist-list

***
Retrieves the organizational Safe List entries.

#### Base Command

`proofpoint-ctr-safelist-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The PPS Cluster ID. | Required |
| limit | The maximum number of entries to return. Default is 50. Default is 50. | Optional |
| all_results | If true, ignore the limit and return all Safe List entries. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofPointCloud.SafeList.attribute | String | The entry attribute. |
| ProofPointCloud.SafeList.operator | String | The entry operator. |
| ProofPointCloud.SafeList.value | String | The entry value. |
| ProofPointCloud.SafeList.comment | String | The entry comment. |

### proofpoint-ctr-blocklist-list

***
Retrieves the organizational Block List entries.

#### Base Command

`proofpoint-ctr-blocklist-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The PPS Cluster ID. | Required |
| limit | The maximum number of entries to return. Default is 50. Default is 50. | Optional |
| all_results | If true, ignore the limit and return all Block List entries. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofPointCloud.BlockList.attribute | String | The entry attribute. |
| ProofPointCloud.BlockList.operator | String | The entry operator. |
| ProofPointCloud.BlockList.value | String | The entry value. |
| ProofPointCloud.BlockList.comment | String | The entry comment. |

### proofpoint-ctr-message-download

***
Downloads a Proofpoint Cloud Threat Response message as an EML file into the War Room. This feature is currently functional only for CTR instances hosted in the US region.

#### Base Command

`proofpoint-ctr-message-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The ID of the message to download. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The name of the downloaded EML file. |
| File.EntryID | String | The War Room entry ID of the downloaded file. |
| File.Size | Number | The size of the downloaded file. |
| File.SHA256 | String | The SHA256 hash of the downloaded file. |
| File.SHA1 | String | The SHA1 hash of the downloaded file. |
| File.MD5 | String | The MD5 hash of the downloaded file. |

### proofpoint-ctr-incident-upload-message

***
Associates an email message with an existing Proofpoint Cloud Threat Response incident.

#### Base Command

`proofpoint-ctr-incident-upload-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident to associate the message with. | Required |
| rfc_message_id | The RFC822 Message-ID of the email. Must include angle brackets. | Required |
| recipient_addresses | A comma-separated list of recipient email addresses. | Required |
| sender | The sender email address. | Optional |
| subject | The email subject. | Optional |
| disposition | The disposition of the message. Possible values are: bulk, clean, impostor, in_progress, internal, low_risk, malware, manual_review, not_set, phish, scam, simulated_phish, spam, suspicious, tap_false_positive, toad, vendor. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofPointCloud.Incident.Message.rfcMessageId | String | The RFC Message ID of the uploaded message. |
| ProofPointCloud.Incident.Message.incident_id | String | The incident ID the message was associated with. |
| ProofPointCloud.Incident.Message.incidentDisplayId | Number | The incident display ID. |
| ProofPointCloud.Incident.Message.uploadedRecipientsCount | Number | The number of recipients uploaded. |

### proofpoint-ctr-blocklist-remove-entry

***
Removes an entry from the organizational Block List.

#### Base Command

`proofpoint-ctr-blocklist-remove-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The PPS Cluster ID. | Required |
| attribute | The attribute of the entry to remove. Possible values are: from, hfrom, ip, host, helo, rcpt. | Required |
| operator | The operator of the entry to remove. Possible values are: equal, not_equal, contain, not_contain, is_in_list. | Required |
| value | The value for the entry. | Required |

#### Context Output

There is no context output for this command.

### proofpoint-ctr-blocklist-add-entry

***
Adds an entry to the organizational Block List.

#### Base Command

`proofpoint-ctr-blocklist-add-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_id | The PPS Cluster ID. | Required |
| attribute | The attribute to filter on. Possible values are: from, hfrom, ip, host, helo, rcpt. | Required |
| operator | The operator to use. Possible values are: equal, not_equal, contain, not_contain, is_in_list. | Required |
| value | The value for the entry. | Required |
| comment | An optional comment for the entry. | Optional |

#### Context Output

There is no context output for this command.

### proofpoint-ctr-run-workflow

***
Runs a Proofpoint Cloud Threat Response manual workflow on the specified incident or message IDs, and polls for the run result. Only workflows listed in the Manual Workflows tab (Responses -> Automation Workflows) can be triggered.

#### Base Command

`proofpoint-ctr-run-workflow`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workflow_id | The ID of the workflow to run. | Required |
| target_ids | A comma-separated list of incident or message IDs to run the workflow on. | Required |
| polling | Use Cortex XSOAR built-in polling to retrieve the result when it is ready. Possible values are: true, false. Default is true. | Optional |
| interval_in_seconds | Interval in seconds between each poll. Default is 30. | Optional |
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofPointCloud.Workflow.id | String | The workflow run ID. |
| ProofPointCloud.Workflow.state | String | The state of the workflow run \(IN_PROGRESS, SUCCESS, FAILED, CANCELLED\). |
| ProofPointCloud.Workflow.workflowId | String | The workflow definition ID. |
| ProofPointCloud.Workflow.createdAt | Date | The run creation timestamp. |
| ProofPointCloud.Workflow.updatedAt | Date | The run last-update timestamp. |
