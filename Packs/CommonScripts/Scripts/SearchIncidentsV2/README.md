Searches Demisto incidents
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Demisto Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* ExtraHop - Ticket Tracking
* SafeBreach - Create Incidents per Insight and Associate Indicators
* Send Investigation Summary Reports

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| id | A comma-separated list of incident IDs by which to filter the results. |
| name | A comma-separated list of incident names by which to filter the results. |
| status | A comma-separated list of incident statuses by which to filter the results. For example: assigned. |
| notstatus | A comma-separated list of incident statuses to exclude from the results.  For example: assigned. |
| reason | A comma-separated list of incident close reasons by which to filter the results. |
| fromdate | Filter by from date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\) |
| todate | Filter by to date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\) |
| fromclosedate | Filter by from close date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\) |
| toclosedate | Filter by to close date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\) |
| fromduedate | Filter by from due date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\) |
| toduedate | Filter by to due date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\) |
| level | Filter by Severity |
| owner | Filter by incident owners |
| details | Filter by incident details |
| type | Filter by incident type |
| query | Use free form query \(use Lucene syntax\) as filter. All other filters will be ignored when this filter is used. |
| page | Filter by the page number |
| size | Number of incidents per page \(per fetch\) |
| sort | Sort in format of field.asc,field.desc,... |

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

