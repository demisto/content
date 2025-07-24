Searches Cortex issues.

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
* MDE - False Positive issue Handling
* MDE - True Positive issue Handling
* Prisma Cloud Correlate Alerts v2
* Ransomware Enrich and Contain
* SafeBreach - Create issues per Insight and Associate Indicators
* SolarStorm and SUNBURST Hunting and Response Playbook
* Spring Core and Cloud Function SpEL RCEs

<!--
Used In: list was truncated. Full list commented out for reference:

Assign Active issues to Next Shift V2
CVE-2021-40444 - MSHTML RCE
Cortex XDR - PrintNightmare Detection and Response
DSAR Inventa Handler
Endpoint Investigation Plan
Enrichment for Verdict
ExtraHop - Ticket Tracking
ExtraHop - Ticket Tracking v2
HAFNIUM - Exchange 0-day exploits
Kaseya VSA  0-day - REvil Ransomware Supply Chain Attack
MDE - False Positive issue Handling
MDE - True Positive issue Handling
NGFW Scan
NOBELIUM - wide scale APT29 spear-phishing
NSA - 5 Security Vulnerabilities Under Active Nation-State Attack
Phishing Alerts Investigation
Prisma Cloud Correlate Alerts v2
Ransomware Enrich and Contain
SafeBreach - Create issues per Insight and Associate Indicators
Send Investigation Summary Reports
Shift handover
SolarStorm and SUNBURST Hunting and Response Playbook
Spring Core and Cloud Function SpEL RCEs
 -->

## Inputs

---

| **Argument Name**  | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|--------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id                 | A comma-separated list of issue IDs by which to filter the results.                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| name               | A comma-separated list of issue names by which to filter the results.                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| status             | A comma-separated list of issue statuses by which to filter the results. For example: assigned.                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| notstatus          | A comma-separated list of issue statuses to exclude from the results.  For example: assigned.                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reason             | A comma-separated list of issue close reasons by which to filter the results.                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| fromdate           | Filter by from date \(e.g. "3 days ago" or 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| todate             | Filter by to date \(e.g. "3 days ago" or 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| fromclosedate      | Filter by from close date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| toclosedate        | Filter by to close date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| fromduedate        | Filter by from due date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| toduedate          | Filter by to due date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\)                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| level              | Filter by Severity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| owner              | Filter by issue owners                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| details            | Filter by issue details                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type               | Filter by issue type                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| query              | Use free form query \(use Lucene syntax\) as filter. All other filters will be ignored when this filter is used.                                                                                                                                                                                                                                                                                                                                                                                                                            |
| page               | Filter by the page number (deprecated)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| trimevents         | The number of events to return from the alert JSON. The default is 0, which returns all events.<br/>Note that the count is from the head of the list, regardless of event time or other properties.                                                                                                                                                                                                                                                                                                                                         |
| size               | Number of issues per page \(per fetch\) (deprecated)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| sort               | Sort in format of field.asc,field.desc,...                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| searchresultslabel | If provided, the value of this argument will be set under the searchResultsLabel context key for each issue found.                                                                                                                                                                                                                                                                                                                                                                                                                       |
| summarizedversion  | If enabled runs a summarized version of this script. Disables auto-extract, sets fromDate to 30 days, and minimizes the context output. You can add sepcific fields to context using the add_fields_to_summarize_context argument. Default is false.                                                                                                                                                                                                                                                                                        |
| includeinformational | Supported only in XSIAM. When the value is set to 'True', informational severity alerts will return as part of the results. The ‘fromdate’ and ‘todate’ arguments must be provided to use this argument. The maximum value currently supported for the 'fromdate' argument to retrieve informational issues is 5 hours. If a value greater than this is provided, it will be adjusted to 5 hours ago. To retrieve only informational issues, use the `query` argument and include this limitation within the query. Default is false. |
| limit              | The maximum number of issues to be returned. Default is 100.                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| foundissues.id | A list of issue IDs returned from the query. | Unknown |
| foundissues.name | A list of issue names returned from the query. | Unknown |
| foundissues.severity | A list of issue severities returned from the query. | Unknown |
| foundissues.status | A list of issue statuses returned from the query. | Unknown |
| foundissues.owner | A list of issue owners returned from the query. | Unknown |
| foundissues.created | A list of the issue create date returned from the query. | Unknown |
| foundissues.closed | A list of issue close dates returned from the query. | Unknown |
| foundissues.labels | An array of labels per issue returned from the query. | Unknown |
| foundissues.details | Details of the issues returned from the query. | Unknown |
| foundissues.dueDate | A list of issue due dates returned from the query. | Unknown |
| foundissues.phase | A list of issue phases returned from the query. | Unknown |
| foundissues.searchResultsLabel| The value provided in the searchresultslabel argument. | String |

## Script Example

```!SearchissuesV2 name="issue to search"```

## Context Example

```
{
    "foundissues": [
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
            "linkedissues": null,
            "modified": "2020-09-29T17:29:44.162202+03:00",
            "name": "issue to search",
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
            "rawName": "issue to search",
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

### issues found

|id|name|severity|status|owner|created|closed|
|---|---|---|---|---|---|---|
| 978 | issue to search | 0 | 0 | admin | 2020-09-29T17:29:44.162034+03:00 | 0001-01-01T00:00:00Z |
