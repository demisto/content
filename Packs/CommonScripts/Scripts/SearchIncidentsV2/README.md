Searches Demisto incidents. A summarized version of this scrips is available with the summarizedversion argument.

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: <~XSOAR>For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.</~XSOAR><~XSIAM>[https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Permission-Management](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Permission-Management)</~XSIAM>

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
Sample usage of this script can be found in the following playbooks and scripts.
* Endpoint Investigation Plan
* ExtraHop - Ticket Tracking
* Kaseya VSA  0-day - REvil Ransomware Supply Chain Attack
* MDE - False Positive Incident Handling
* MDE - True Positive Incident Handling
* Prisma Cloud Correlate Alerts v2
* Ransomware Enrich and Contain
* SafeBreach - Create Incidents per Insight and Associate Indicators
* SolarStorm and SUNBURST Hunting and Response Playbook
* Spring Core and Cloud Function SpEL RCEs

<!--
Used In: list was truncated. Full list commented out for reference:

Assign Active Incidents to Next Shift V2
CVE-2021-40444 - MSHTML RCE
Cortex XDR - PrintNightmare Detection and Response
DSAR Inventa Handler
Endpoint Investigation Plan
Enrichment for Verdict
ExtraHop - Ticket Tracking
ExtraHop - Ticket Tracking v2
HAFNIUM - Exchange 0-day exploits
Kaseya VSA  0-day - REvil Ransomware Supply Chain Attack
MDE - False Positive Incident Handling
MDE - True Positive Incident Handling
NGFW Scan
NOBELIUM - wide scale APT29 spear-phishing
NSA - 5 Security Vulnerabilities Under Active Nation-State Attack
Phishing Alerts Investigation
Prisma Cloud Correlate Alerts v2
Ransomware Enrich and Contain
SafeBreach - Create Incidents per Insight and Associate Indicators
Send Investigation Summary Reports
Shift handover
SolarStorm and SUNBURST Hunting and Response Playbook
Spring Core and Cloud Function SpEL RCEs
 -->

## Inputs
---

| **Argument Name**  | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|--------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id                 | A comma-separated list of incident IDs by which to filter the results.                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| name               | A comma-separated list of incident names by which to filter the results.                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| status             | A comma-separated list of incident statuses by which to filter the results. For example: assigned.                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| notstatus          | A comma-separated list of incident statuses to exclude from the results.  For example: assigned.                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reason             | A comma-separated list of incident close reasons by which to filter the results.                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| fromdate           | Filter by from date \(e.g. "3 days ago" or 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| todate             | Filter by to date \(e.g. "3 days ago" or 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| fromclosedate      | Filter by from close date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| toclosedate        | Filter by to close date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| fromduedate        | Filter by from due date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| toduedate          | Filter by to due date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| level              | Filter by Severity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| owner              | Filter by incident owners                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| details            | Filter by incident details                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type               | Filter by incident type                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| query              | Use free form query \(use Lucene syntax\) as filter. All other filters will be ignored when this filter is used.                                                                                                                                                                                                                                                                                                                                                                                                                            |
| page               | Filter by the page number (deprecated)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| trimevents         | The number of events to return from the alert JSON. The default is 0, which returns all events.<br/>Note that the count is from the head of the list, regardless of event time or other properties.                                                                                                                                                                                                                                                                                                                                         |
| size               | Number of incidents per page \(per fetch\) (deprecated)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| sort               | Sort in format of field.asc,field.desc,...                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| searchresultslabel | If provided, the value of this argument will be set under the searchResultsLabel context key for each incident found.                                                                                                                                                                                                                                                                                                                                                                                                                       |
| summarizedversion  | If enabled runs a summarized version of this script. Disables auto-extract, sets fromDate to 30 days, and minimizes the context output. You can add sepcific fields to context using the add_fields_to_summarize_context argument. Default is false.                                                                                                                                                                                                                                                                                        |
| includeinformational | Supported only in XSIAM. When the value is set to 'True', informational severity alerts will return as part of the results. The ‘fromdate’ and ‘todate’ arguments must be provided to use this argument. The maximum value currently supported for the 'fromdate' argument to retrieve informational incidents is 5 hours. If a value greater than this is provided, it will be adjusted to 5 hours ago. To retrieve only informational incidents, use the `query` argument and include this limitation within the query. Default is false. |
| limit              | The maximum number of incidents to be returned. Default is 100.                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| foundIncidents.id | A list of incident IDs returned from the query. | Unknown |
| foundIncidents.name | A list of incident names returned from the query. | Unknown |
| foundIncidents.severity | A list of incident severities returned from the query. | Unknown |
| foundIncidents.status | A list of incident statuses returned from the query. | Unknown |
| foundIncidents.owner | A list of incident owners returned from the query. | Unknown |
| foundIncidents.created | A list of the incident create date returned from the query. | Unknown |
| foundIncidents.closed | A list of incident close dates returned from the query. | Unknown |
| foundIncidents.labels | An array of labels per incident returned from the query. | Unknown |
| foundIncidents.details | Details of the incidents returned from the query. | Unknown |
| foundIncidents.dueDate | A list of incident due dates returned from the query. | Unknown |
| foundIncidents.phase | A list of incident phases returned from the query. | Unknown |
| foundIncidents.searchResultsLabel| The value provided in the searchresultslabel argument. | String |


## Script Example
```!SearchIncidentsV2 name="Incident to search"```

## Context Example
```
{
    "foundIncidents": [
        {
            "CustomFields": {
                "detectionsla": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 20,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "remediationsla": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 7200,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "timetoassignment": {
                    "accumulatedPause": 0,
                    "breachTriggered": false,
                    "dueDate": "0001-01-01T00:00:00Z",
                    "endDate": "0001-01-01T00:00:00Z",
                    "lastPauseDate": "0001-01-01T00:00:00Z",
                    "runStatus": "idle",
                    "sla": 0,
                    "slaStatus": -1,
                    "startDate": "0001-01-01T00:00:00Z",
                    "totalDuration": 0
                },
                "urlsslverification": []
            },
            "ShardID": 0,
            "account": "",
            "activated": "0001-01-01T00:00:00Z",
            "allRead": false,
            "allReadWrite": false,
            "attachment": null,
            "autime": 1601389784162034000,
            "canvases": null,
            "category": "",
            "closeNotes": "",
            "closeReason": "",
            "closed": "0001-01-01T00:00:00Z",
            "closingUserId": "",
            "created": "2020-09-29T17:29:44.162034+03:00",
            "dbotCreatedBy": "admin",
            "dbotCurrentDirtyFields": null,
            "dbotDirtyFields": null,
            "dbotMirrorDirection": "",
            "dbotMirrorId": "",
            "dbotMirrorInstance": "",
            "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
            "dbotMirrorTags": null,
            "details": "",
            "droppedCount": 0,
            "dueDate": "2020-10-09T17:29:44.162034+03:00",
            "feedBased": false,
            "hasRole": false,
            "id": "978",
            "investigationId": "",
            "isPlayground": false,
            "labels": [
                {
                    "type": "Instance",
                    "value": "admin"
                },
                {
                    "type": "Brand",
                    "value": "Manual"
                }
            ],
            "lastJobRunTime": "0001-01-01T00:00:00Z",
            "lastOpen": "0001-01-01T00:00:00Z",
            "linkedCount": 0,
            "linkedIncidents": null,
            "modified": "2020-09-29T17:29:44.162202+03:00",
            "name": "Incident to search",
            "notifyTime": "0001-01-01T00:00:00Z",
            "occurred": "2020-09-29T17:29:44.162034+03:00",
            "openDuration": 0,
            "owner": "admin",
            "parent": "",
            "phase": "",
            "playbookId": "",
            "previousAllRead": false,
            "previousAllReadWrite": false,
            "previousRoles": null,
            "rawCategory": "",
            "rawCloseReason": "",
            "rawJSON": "",
            "rawName": "Incident to search",
            "rawPhase": "",
            "rawType": "Unclassified",
            "reason": "",
            "reminder": "0001-01-01T00:00:00Z",
            "roles": null,
            "runStatus": "",
            "severity": 0,
            "sla": 0,
            "sortValues": [
                "_score"
            ],
            "sourceBrand": "Manual",
            "sourceInstance": "admin",
            "status": 0,
            "type": "Unclassified",
            "version": 1
        }
    ]
}
```

## Human Readable Output
### Incidents found
|id|name|severity|status|owner|created|closed|
|---|---|---|---|---|---|---|
| 978 | Incident to search | 0 | 0 | admin | 2020-09-29T17:29:44.162034+03:00 | 0001-01-01T00:00:00Z |

