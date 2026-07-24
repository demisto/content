Use the Google SecOps Cases integration to retrieve Cases as Incidents. This integration also provides commands to manage the Cases lifecycle.
This integration was integrated and tested with version v1 Alpha of Google SecOps API.

## Configure Google SecOps Cases in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| User's Service Account JSON |  | True |
| API URL Format | Select the API URL format to use for API requests. Default value is '&lt;chronicle&gt;.&lt;REGION&gt;.&lt;rep.googleapis.com&gt;'. | False |
| Google SecOps Project Instance ID | Provide the Project Instance ID of the Google SecOps.<br/><br/>Note: User can retrieve the Customer ID\(Project Instance ID\) in the Profile section of the Google SecOps page. | True |
| Google SecOps Project Number | Provide the Project Number of the Google SecOps.<br/><br/>Note: User can retrieve the Project Number in the Profile section of the Google SecOps page. If Project Number is not provided, then Project ID\(from Service Account JSON\) will be used. | False |
| Region | Select the region based on the location of the Google SecOps instance. If the region is not listed in the dropdown, choose the "Other" option and specify the region in the "Other Region" text field. | True |
| Other Region | Specify the region based on the location of the Google SecOps instance. Only applicable if the "Other" option is selected in the Region dropdown. | False |
| Fetch incidents |  |  |
| Incident type |  | False |
| First Fetch Time | The UTC date or relative timestamp from where to start fetching incidents. Default is 3 days.<br/><br/>Note: If the value is greater than the past 7 days, it will be considered as past 7 days. The maximum is 7 days.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 01 May 2026 04:45:33, 2026-05-17T14:05:44Z. | False |
| How many incidents to fetch each time | The maximum number of incidents to fetch in each time. Default is 50.<br/><br/>Note: If the value is greater than 200, it will be considered as 200. The maximum is 200. | False |
| Case Priorities | Filter cases by priority level. Default is all. | False |
| Case Statuses | Filter cases by status. Default is all. | False |
| Case Environments | Filter cases by logical environment. | False |
| Case Tags | Filter cases by tag name. | False |
| Case Filter Logic | Logical operator to combine the case filter parameters. Default is AND. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gcb-case-list

***
Retrieve the list of cases.

#### Base Command

`gcb-case-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| display_name | Filter the cases by display name. Supports comma-separated values. | Optional |
| priority | Filter the cases by priority. Supports comma-separated values. Possible values are: UNSPECIFIED, INFO, LOW, MEDIUM, HIGH, CRITICAL. | Optional |
| status | Filter the cases by status. Supports comma-separated values. Possible values are: OPENED, CLOSED, MERGED, CREATION_PENDING, CASE_DATA_STATE_UNSPECIFIED. | Optional |
| type | Filter the cases by type. Supports comma-separated values. Possible values are: EXTERNAL, TEST, REQUEST, CASE_TYPE_UNSPECIFIED. | Optional |
| stage | Filter the cases by stage. Supports comma-separated values. Possible values are: Triage, Incident, Investigation. | Optional |
| source | Filter the cases by source. Supports comma-separated values. Possible values are: Server, User, Simulated, Merge, AlertMove. | Optional |
| assignee | Filter the cases by assignee user email or SOC role. Supports comma-separated values. | Optional |
| environment | Filter the cases by environment assigned to the case. Supports comma-separated values. | Optional |
| tags | Filter the cases by tag names. Supports comma-separated values. | Optional |
| products | Filter the cases by product name. Supports comma-separated values. | Optional |
| important | Filter the cases by the importance flag. Possible values are: True, False. | Optional |
| incident | Filter the cases by the incident flag. Possible values are: True, False. | Optional |
| workflow_status | Filter the cases by playbook or workflow execution status. Supports comma-separated values. Possible values are: NONE, IN_PROGRESS, COMPLETED, FAILED, TERMINATED, PENDING_IN_QUEUE, PENDING_FOR_USER, WORKFLOW_STATUS_UNSPECIFIED. | Optional |
| sla | Filter the cases by SLA expiration status. Supports comma-separated values. Possible values are: OPEN_SLA, PASSED_DUE, NO_SLA, CRITICAL_EXPIRED, PAUSED, SLA_EXPIRATION_STATUS_UNSPECIFIED. | Optional |
| alerts_sla | Filter the cases by the aggregated alerts SLA expiration status. Supports comma-separated values. Possible values are: OPEN_SLA, PASSED_DUE, NO_SLA, CRITICAL_EXPIRED, PAUSED, SLA_EXPIRATION_STATUS_UNSPECIFIED. | Optional |
| create_start_time | Filter the cases created on or after this time.<br/><br/>Note: Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 2026-05-17T14:05:44Z. | Optional |
| create_end_time | Filter the cases created on or before this time.<br/><br/>Note: Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 2026-05-17T14:05:44Z. | Optional |
| update_start_time | Filter the cases updated on or after this time.<br/><br/>Note: Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 2026-05-17T14:05:44Z. | Optional |
| update_end_time | Filter the cases updated on or before this time.<br/><br/>Note: Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 2026-05-17T14:05:44Z. | Optional |
| advanced_filter | Specify a raw AIP-160 filter string for advanced conditions. When provided, all other individual filter arguments are ignored.<br/><br/>Supported values: displayName, creatorUserId, creatorUser, assignee, stage, status, priority, important, type, environment, score, alertsSla.expirationStatus, sla.expirationStatus, tags, products, closureDetails, tasks, workflowStatus, createTime, updateTime<br/><br/>Example: (priority="PRIORITY_HIGH" OR status="OPENED") AND stage="Investigation". | Optional |
| page_size | Specify the maximum number of cases to return.<br/><br/>Note: Maximum value is 1000. Default is 50. | Optional |
| page_token | Specify the page token for pagination.<br/><br/>Note: Use the next_page_token from a previous gcb-case-list response. | Optional |
| sort_by | Specify the field to sort results by. Possible values are: displayName, priority, stage, status, score, createTime, updateTime, assignee, environment, type, sla.expirationTime, alertsSla.expirationTime, sla.expirationStatus, alertsSla.expirationStatus, workflowStatus. Default is createTime. | Optional |
| sort_order | Specify the sort direction for the results. Possible values are: Asc, Desc. Default is Desc. | Optional |
| filter_logic | Specify the logical operator to combine filter conditions. Possible values are: AND, OR. Default is AND. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.name | String | The unique resource name of the Case. |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.displayName | String | The title of the Case. |
| GoogleSecOps.Case.creatorUserId | String | The ID of the user who created the Case. |
| GoogleSecOps.Case.lastModifyingUserId | String | The ID of the user who last modified the Case. |
| GoogleSecOps.Case.createTime | String | The creation time of the Case \(unix epoch milliseconds\). |
| GoogleSecOps.Case.updateTime | String | The last update time of the Case \(unix epoch milliseconds\). |
| GoogleSecOps.Case.alertCount | Number | The number of alerts linked to the Case. |
| GoogleSecOps.Case.stage | String | The current workflow stage of the Case. |
| GoogleSecOps.Case.priority | String | The priority of the Case. |
| GoogleSecOps.Case.assignee | String | The assigned user or SOC role of the Case. |
| GoogleSecOps.Case.description | String | The description of the Case. |
| GoogleSecOps.Case.type | String | The type of the Case. |
| GoogleSecOps.Case.environment | String | The logical environment of the Case. |
| GoogleSecOps.Case.status | String | The status of the Case. |
| GoogleSecOps.Case.score | Number | The attack exposure score of the Case. |
| GoogleSecOps.Case.workflowStatus | String | The playbook or workflow status of the Case. |
| GoogleSecOps.Case.source | String | The source that created the Case. |
| GoogleSecOps.Case.important | Boolean | Whether the Case is marked as important. |
| GoogleSecOps.Case.incident | Boolean | Whether the Case is marked as an incident. |
| GoogleSecOps.Case.overflowCase | Boolean | Whether the Case is an overflow case due to large data volume. |
| GoogleSecOps.Case.involvedSuspiciousEntity | Boolean | Whether a suspicious entity is involved in the Case. |
| GoogleSecOps.Case.sla.expirationTime | String | The SLA expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.sla.criticalExpirationTime | String | The SLA critical expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.sla.expirationStatus | String | The SLA expiration status of the Case. |
| GoogleSecOps.Case.sla.remainingTimeSinceLastPause | Number | The remaining time since the last SLA pause of the Case. |
| GoogleSecOps.Case.alertsSla.expirationTime | String | The aggregated alerts SLA expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.alertsSla.criticalExpirationTime | String | The aggregated alerts SLA critical expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.alertsSla.expirationStatus | String | The aggregated alerts SLA expiration status. |
| GoogleSecOps.Case.alertsSla.remainingTimeSinceLastPause | Number | The remaining time since the last alerts SLA pause of the Case. |
| GoogleSecOps.Case.tags.displayName | String | The display name of the tag. |
| GoogleSecOps.Case.tags.priority | Number | The priority order of the tag. |
| GoogleSecOps.Case.products.displayName | String | The display name of the product. |
| GoogleSecOps.Case.products.alert | String | The resource name of the alert associated with the product. |
| GoogleSecOps.Case.tasks.id | String | The ID of the task. |
| GoogleSecOps.Case.tasks.title | String | The title of the task. |
| GoogleSecOps.Case.tasks.content | String | The content/description of the task. |
| GoogleSecOps.Case.tasks.status | String | The status of the task. |
| GoogleSecOps.Case.tasks.assignee | String | The assignee of the task. |
| GoogleSecOps.Case.tasks.author | String | The author who created the task. |
| GoogleSecOps.Case.tasks.lastAuthor | String | The last user who modified the task. |
| GoogleSecOps.Case.tasks.createTime | String | The creation time of the task \(unix epoch milliseconds\). |
| GoogleSecOps.Case.tasks.updateTime | String | The last update time of the task \(unix epoch milliseconds\). |
| GoogleSecOps.Case.tasks.caseId | Number | The ID of the Case the task belongs to. |
| GoogleSecOps.Case.tasks.favorite | Boolean | Whether the task is marked as a favorite. |
| GoogleSecOps.Case.closureDetails.reason | String | The closure reason of the Case. |
| GoogleSecOps.Case.closureDetails.comment | String | The closure comment of the Case. |
| GoogleSecOps.Case.closureDetails.rootCause | String | The root cause provided at closure. |
| GoogleSecOps.Case.closureDetails.caseClosedAction | String | The action taken when the Case was closed. |
| GoogleSecOps.PageToken.command | String | The command name associated with the pagination token. |
| GoogleSecOps.PageToken.nextPageToken | String | The token to retrieve the next page of Cases. |
| GoogleSecOps.PageToken.totalSize | Number | The total number of cases available. |

#### Command example

```!gcb-case-list page_size=10 priority="HIGH,CRITICAL" status=OPENED stage=Triage assignee=@SOC sort_by=createTime sort_order=Desc```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": [
            {
                "name": "projects/chronicle-mock-proj/locations/us/instances/00000000-0000-0000-0000-000000000001/cases/1001",
                "caseId": "1001",
                "displayName": "Test Case 1",
                "lastModifyingUserId": "00000000-0000-0000-0000-000000000002",
                "createTime": "1778778979232",
                "updateTime": "1779426987796",
                "alertCount": 15,
                "stage": "Triage",
                "priority": "PRIORITY_MEDIUM",
                "assignee": "@Tier1",
                "type": "EXTERNAL",
                "environment": "Default Environment",
                "status": "OPENED",
                "workflowStatus": "PENDING_FOR_USER",
                "source": "Server",
                "important": false,
                "incident": false,
                "overflowCase": false,
                "involvedSuspiciousEntity": false,
                "sla": {
                    "expirationTime": "1780832620238",
                    "criticalExpirationTime": "1780580620238",
                    "expirationStatus": "OPEN_SLA"
                },
                "alertsSla": {
                    "expirationTime": "1782774000000",
                    "expirationStatus": "OPEN_SLA"
                },
                "tags": [
                    {
                        "displayName": "demo 1",
                        "priority": 0
                    },
                    {
                        "displayName": "demo 2",
                        "priority": 1
                    }
                ],
                "products": [
                    {
                        "displayName": "Test Case",
                        "alert": "alert 1"
                    },
                    {
                        "displayName": "Test Case",
                        "alert": "alert 2"
                    }
                ],
                "tasks": [
                    {
                        "id": "3",
                        "createTime": "1779447705049",
                        "updateTime": "1779447705049",
                        "content": "Testing",
                        "title": "XSOAR testing",
                        "author": "00000000-0000-0000-0000-000000000001",
                        "lastAuthor": "00000000-0000-0000-0000-000000000002",
                        "assignee": "00000000-0000-0000-0000-000000000001",
                        "status": "PENDING",
                        "favorite": false,
                        "caseId": 1001
                    }
                ],
                "closureDetails": {
                    "reason": "NOT_MALICIOUS",
                    "rootCause": "False positive from detection rule",
                    "caseClosedAction": "MANUALLY",
                    "comment": "Reviewed and confirmed benign activity.\n Case closed by Siemplify API. \nAll attached playbooks and playbook blocks have been terminated.\nAll Alerts were closed."
                }
            },
            {
                "name": "projects/chronicle-mock-proj/locations/us/instances/00000000-0000-0000-0000-000000000001/cases/1002",
                "caseId": "1002",
                "displayName": "Test Case 2",
                "lastModifyingUserId": "00000000-0000-0000-0000-000000000003",
                "createTime": "1778714179967",
                "updateTime": "1779416182426",
                "alertCount": 5,
                "stage": "Investigation",
                "priority": "PRIORITY_HIGH",
                "assignee": "00000000-0000-0000-0000-000000000004",
                "type": "EXTERNAL",
                "environment": "Production",
                "status": "OPENED",
                "workflowStatus": "IN_PROGRESS",
                "source": "Agent",
                "important": true,
                "incident": false,
                "overflowCase": false,
                "involvedSuspiciousEntity": true,
                "sla": {
                    "expirationStatus": "NO_SLA"
                },
                "alertsSla": {
                    "expirationStatus": "NO_SLA"
                },
                "tags": [
                    {
                        "displayName": "critical",
                        "priority": 0
                    }
                ],
                "products": [
                    {
                        "displayName": "Test Product",
                        "alert": "alert 3"
                    }
                ]
            }
        ],
        "PageToken": {
            "command": "gcb-case-list",
            "nextPageToken": "next_page_token_value",
            "totalSize": 2
        }
    }
}
```

#### Human Readable Output

>### Case List
>
>|Case ID|Display Name|Priority|Status|Stage|Environment|Workflow Status|Assignee|Tags|SLA|Alert Count|Create Time|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1001 | Test Case 1 | MEDIUM | OPENED | Triage | Default Environment | PENDING_FOR_USER | @Tier1 | **-** ***displayName***: demo 1<br/> ***priority***: 0<br/>**-** ***displayName***: demo 2<br/> ***priority***: 1 | ***Status***: OPEN_SLA<br/>***Expiration Time***: 2026-06-07 11:43:40 UTC<br/>***Critical Expiration Time***: 2026-06-04 13:43:40 UTC | 15 | 2026-05-14 17:16:19 UTC |
>| 1002 | Test Case 2 | HIGH | OPENED | Investigation | Production | IN_PROGRESS | 00000000-0000-0000-0000-000000000004 | **-** ***displayName***: critical<br/> ***priority***: 0 | ***Status***: NO_SLA | 5 | 2026-05-13 23:16:19 UTC |
>
>Maximum number of cases specified in page_size has been returned. To fetch the next set of cases, execute the command with the page token as `next_page_token_value`.

### gcb-case-get

***
Retrieve a specific case by its ID.

#### Base Command

`gcb-case-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.name | String | The unique resource name of the Case. |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.displayName | String | The title of the Case. |
| GoogleSecOps.Case.creatorUserId | String | The ID of the user who created the Case. |
| GoogleSecOps.Case.lastModifyingUserId | String | The ID of the user who last modified the Case. |
| GoogleSecOps.Case.createTime | String | The creation time of the Case \(unix epoch milliseconds\). |
| GoogleSecOps.Case.updateTime | String | The last update time of the Case \(unix epoch milliseconds\). |
| GoogleSecOps.Case.alertCount | Number | The number of alerts linked to the Case. |
| GoogleSecOps.Case.stage | String | The current workflow stage of the Case. |
| GoogleSecOps.Case.priority | String | The priority of the Case. |
| GoogleSecOps.Case.assignee | String | The assigned user or SOC role of the Case. |
| GoogleSecOps.Case.description | String | The description of the Case. |
| GoogleSecOps.Case.type | String | The type of the Case. |
| GoogleSecOps.Case.environment | String | The logical environment of the Case. |
| GoogleSecOps.Case.status | String | The status of the Case. |
| GoogleSecOps.Case.score | Number | The attack exposure score of the Case. |
| GoogleSecOps.Case.workflowStatus | String | The playbook or workflow status of the Case. |
| GoogleSecOps.Case.source | String | The source that created the Case. |
| GoogleSecOps.Case.important | Boolean | Whether the Case is marked as important. |
| GoogleSecOps.Case.incident | Boolean | Whether the Case is marked as an incident. |
| GoogleSecOps.Case.overflowCase | Boolean | Whether the Case is an overflow case due to large data volume. |
| GoogleSecOps.Case.involvedSuspiciousEntity | Boolean | Whether a suspicious entity is involved in the Case. |
| GoogleSecOps.Case.sla.expirationTime | String | The SLA expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.sla.criticalExpirationTime | String | The SLA critical expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.sla.expirationStatus | String | The SLA expiration status of the Case. |
| GoogleSecOps.Case.sla.remainingTimeSinceLastPause | Number | The remaining time since the last SLA pause of the Case. |
| GoogleSecOps.Case.alertsSla.expirationTime | String | The aggregated alerts SLA expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.alertsSla.criticalExpirationTime | String | The aggregated alerts SLA critical expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.alertsSla.expirationStatus | String | The aggregated alerts SLA expiration status. |
| GoogleSecOps.Case.alertsSla.remainingTimeSinceLastPause | Number | The remaining time since the last alerts SLA pause of the Case. |
| GoogleSecOps.Case.tags.displayName | String | The display name of the tag. |
| GoogleSecOps.Case.tags.priority | Number | The priority order of the tag. |
| GoogleSecOps.Case.products.displayName | String | The display name of the product. |
| GoogleSecOps.Case.products.alert | String | The resource name of the alert associated with the product. |
| GoogleSecOps.Case.tasks.id | String | The ID of the task. |
| GoogleSecOps.Case.tasks.title | String | The title of the task. |
| GoogleSecOps.Case.tasks.content | String | The content/description of the task. |
| GoogleSecOps.Case.tasks.status | String | The status of the task. |
| GoogleSecOps.Case.tasks.assignee | String | The assignee of the task. |
| GoogleSecOps.Case.tasks.author | String | The author who created the task. |
| GoogleSecOps.Case.tasks.lastAuthor | String | The last user who modified the task. |
| GoogleSecOps.Case.tasks.createTime | String | The creation time of the task \(unix epoch milliseconds\). |
| GoogleSecOps.Case.tasks.updateTime | String | The last update time of the task \(unix epoch milliseconds\). |
| GoogleSecOps.Case.tasks.caseId | Number | The ID of the Case the task belongs to. |
| GoogleSecOps.Case.tasks.favorite | Boolean | Whether the task is marked as a favorite. |
| GoogleSecOps.Case.closureDetails.reason | String | The closure reason of the Case. |
| GoogleSecOps.Case.closureDetails.comment | String | The closure comment of the Case. |
| GoogleSecOps.Case.closureDetails.rootCause | String | The root cause provided at closure. |
| GoogleSecOps.Case.closureDetails.caseClosedAction | String | The action taken when the Case was closed. |

#### Command example

```!gcb-case-get case_id=1001```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": {
            "name": "projects/chronicle-mock-proj/locations/us/instances/00000000-0000-0000-0000-000000000001/cases/1001",
            "caseId": "1001",
            "displayName": "Test Case",
            "lastModifyingUserId": "00000000-0000-0000-0000-000000000002",
            "createTime": "1778778979232",
            "updateTime": "1779426987796",
            "alertCount": 15,
            "stage": "Triage",
            "priority": "PRIORITY_MEDIUM",
            "important": false,
            "incident": false,
            "assignee": "@Tier1",
            "type": "EXTERNAL",
            "overflowCase": false,
            "environment": "Default Environment",
            "status": "OPENED",
            "workflowStatus": "PENDING_FOR_USER",
            "sla": {
                "expirationTime": "1780832620238",
                "criticalExpirationTime": "1780580620238",
                "expirationStatus": "OPEN_SLA"
            },
            "alertsSla": {
                "expirationTime": "1782774000000",
                "expirationStatus": "OPEN_SLA"
            },
            "source": "Server",
            "involvedSuspiciousEntity": false,
            "tags": [
                {"displayName": "demo 1", "priority": 0},
                {"displayName": "demo 2", "priority": 1}
            ],
            "products": [
                {"displayName": "Test Case", "alert": "alert 1"},
                {"displayName": "Test Case", "alert": "alert 2"}
            ],
            "tasks": [
                {
                    "id": "3",
                    "createTime": "1779447705049",
                    "updateTime": "1779447705049",
                    "content": "Testing",
                    "title": "XSOAR testing",
                    "author": "00000000-0000-0000-0000-000000000001",
                    "lastAuthor": "00000000-0000-0000-0000-000000000002",
                    "assignee": "00000000-0000-0000-0000-000000000001",
                    "status": "PENDING",
                    "favorite": false,
                    "caseId": 1001
                }
            ],
            "closureDetails": {
                "reason": "NOT_MALICIOUS",
                "rootCause": "False positive from detection rule",
                "caseClosedAction": "MANUALLY",
                "comment": "Reviewed and confirmed benign activity.\n Case closed by Siemplify API. \nAll attached playbooks and playbook blocks have been terminated.\nAll Alerts were closed."
            }
        }
    }
}
```

#### Human Readable Output

>### Case Information
>
>|Case ID|Display Name|Priority|Status|Stage|Assignee|Alert Count|Type|Environment|Source|Workflow Status|SLA|Alerts SLA|Tags|Create Time|Update Time|Incident|Important|Involved Suspicious Entity|Overflow Case|Last Modifying User ID|Products|Tasks|Closure Details|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1001 | Test Case | MEDIUM | OPENED | Triage | @Tier1 | 15 | EXTERNAL | Default Environment | Server | PENDING_FOR_USER | ***Status***: OPEN_SLA<br/>***Expiration Time***: 2026-06-07 11:43:40 UTC<br/>***Critical Expiration Time***: 2026-06-04 13:43:40 UTC | ***Status***: OPEN_SLA<br/>***Expiration Time***: 2026-06-29 23:00:00 UTC | **-** ***displayName***: demo 1<br/> ***priority***: 0<br/>**-** ***displayName***: demo 2<br/> ***priority***: 1 | 2026-05-14 17:16:19 UTC | 2026-05-22 05:16:27 UTC | False | False | False | False | 00000000-0000-0000-0000-000000000002 | **-** ***displayName***: Test Case<br/> ***alert***: alert 1<br/>**-** ***displayName***: Test Case<br/> ***alert***: alert 2 | **-** ***id***: 3<br/> ***createTime***: 1779447705049<br/> ***updateTime***: 1779447705049<br/> ***content***: Testing<br/> ***title***: XSOAR testing<br/> ***author***: 00000000-0000-0000-0000-000000000001<br/> ***lastAuthor***: 00000000-0000-0000-0000-000000000002<br/> ***assignee***: 00000000-0000-0000-0000-000000000001<br/> ***status***: PENDING<br/> ***favorite***: False<br/> ***caseId***: 1001 | ***reason***: NOT_MALICIOUS<br/>***rootCause***: False positive from detection rule<br/>***caseClosedAction***: MANUALLY<br/>***comment***: Reviewed and confirmed benign activity.<br/> Case closed by Siemplify API. <br/>All attached playbooks and playbook blocks have been terminated.<br/>All Alerts were closed. |

### gcb-case-update

***
Update the properties of a case.

#### Base Command

`gcb-case-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| display_name | Specify the new title for the case.<br/><br/>Note: If the value is greater than 200 characters, it will be truncated to 200 characters. | Optional |
| description | Specify the new description for the case.<br/><br/>Note: If the value is greater than 1000 characters, it will be truncated to 1000 characters. | Optional |
| important | Specify whether to mark the case as important. Possible values are: True, False. | Optional |
| incident | Specify whether to mark the case as an incident. Possible values are: True, False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.name | String | The unique resource name of the Case. |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.displayName | String | The title of the Case. |
| GoogleSecOps.Case.creatorUserId | String | The ID of the user who created the Case. |
| GoogleSecOps.Case.lastModifyingUserId | String | The ID of the user who last modified the Case. |
| GoogleSecOps.Case.createTime | String | The creation time of the Case \(unix epoch milliseconds\). |
| GoogleSecOps.Case.updateTime | String | The last update time of the Case \(unix epoch milliseconds\). |
| GoogleSecOps.Case.alertCount | Number | The number of alerts linked to the Case. |
| GoogleSecOps.Case.stage | String | The current workflow stage of the Case. |
| GoogleSecOps.Case.priority | String | The priority of the Case. |
| GoogleSecOps.Case.assignee | String | The assigned user or SOC role of the Case. |
| GoogleSecOps.Case.description | String | The description of the Case. |
| GoogleSecOps.Case.type | String | The type of the Case. |
| GoogleSecOps.Case.environment | String | The logical environment of the Case. |
| GoogleSecOps.Case.status | String | The status of the Case. |
| GoogleSecOps.Case.score | Number | The attack exposure score of the Case. |
| GoogleSecOps.Case.workflowStatus | String | The playbook or workflow status of the Case. |
| GoogleSecOps.Case.source | String | The source that created the Case. |
| GoogleSecOps.Case.important | Boolean | Whether the Case is marked as important. |
| GoogleSecOps.Case.incident | Boolean | Whether the Case is marked as an incident. |
| GoogleSecOps.Case.overflowCase | Boolean | Whether the Case is an overflow case due to large data volume. |
| GoogleSecOps.Case.involvedSuspiciousEntity | Boolean | Whether a suspicious entity is involved in the Case. |
| GoogleSecOps.Case.sla.expirationTime | String | The SLA expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.sla.criticalExpirationTime | String | The SLA critical expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.sla.expirationStatus | String | The SLA expiration status of the Case. |
| GoogleSecOps.Case.sla.remainingTimeSinceLastPause | Number | The remaining time since the last SLA pause of the Case. |
| GoogleSecOps.Case.alertsSla.expirationTime | String | The aggregated alerts SLA expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.alertsSla.criticalExpirationTime | String | The aggregated alerts SLA critical expiration time of the Case \(unix ms\). |
| GoogleSecOps.Case.alertsSla.expirationStatus | String | The aggregated alerts SLA expiration status. |
| GoogleSecOps.Case.alertsSla.remainingTimeSinceLastPause | Number | The remaining time since the last alerts SLA pause of the Case. |
| GoogleSecOps.Case.tags.displayName | String | The display name of the tag. |
| GoogleSecOps.Case.tags.priority | Number | The priority order of the tag. |
| GoogleSecOps.Case.products.displayName | String | The display name of the product. |
| GoogleSecOps.Case.products.alert | String | The resource name of the alert associated with the product. |
| GoogleSecOps.Case.tasks.id | String | The ID of the task. |
| GoogleSecOps.Case.tasks.title | String | The title of the task. |
| GoogleSecOps.Case.tasks.content | String | The content/description of the task. |
| GoogleSecOps.Case.tasks.status | String | The status of the task. |
| GoogleSecOps.Case.tasks.assignee | String | The assignee of the task. |
| GoogleSecOps.Case.tasks.author | String | The author who created the task. |
| GoogleSecOps.Case.tasks.lastAuthor | String | The last user who modified the task. |
| GoogleSecOps.Case.tasks.createTime | String | The creation time of the task \(unix epoch milliseconds\). |
| GoogleSecOps.Case.tasks.updateTime | String | The last update time of the task \(unix epoch milliseconds\). |
| GoogleSecOps.Case.tasks.caseId | Number | The ID of the Case the task belongs to. |
| GoogleSecOps.Case.tasks.favorite | Boolean | Whether the task is marked as a favorite. |
| GoogleSecOps.Case.closureDetails.reason | String | The closure reason of the Case. |
| GoogleSecOps.Case.closureDetails.comment | String | The closure comment of the Case. |
| GoogleSecOps.Case.closureDetails.rootCause | String | The root cause provided at closure. |
| GoogleSecOps.Case.closureDetails.caseClosedAction | String | The action taken when the Case was closed. |

#### Command example

```!gcb-case-update case_id=1001 display_name="XSOAR 1 Testing" important=True```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": {
            "caseId": "1001",
            "lastModifyingUserId": "Siemplify automation",
            "createTime": "1780569465745",
            "updateTime": "1780912611281",
            "displayName": "XSOAR 1 Testing",
            "alertCount": 1,
            "stage": "Triage",
            "priority": "PRIORITY_LOW",
            "important": true,
            "incident": false,
            "assignee": "00000000-0000-0000-0000-000000000001",
            "type": "EXTERNAL",
            "overflowCase": false,
            "environment": "XSOAR",
            "status": "OPENED",
            "workflowStatus": "NONE",
            "sla": {
                "expirationStatus": "NO_SLA"
            },
            "alertsSla": {
                "expirationStatus": "NO_SLA"
            },
            "source": "User",
            "involvedSuspiciousEntity": false
        }
    }
}
```

#### Human Readable Output

>### Updated Case Information
>
>|Case ID|Display Name|Priority|Status|Stage|Assignee|Alert Count|Type|Environment|Source|Workflow Status|SLA|Alerts SLA|Create Time|Update Time|Incident|Important|Involved Suspicious Entity|Overflow Case|Last Modifying User ID|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1001 | XSOAR 1 Testing | LOW | OPENED | Triage | 00000000-0000-0000-0000-000000000001 | 1 | EXTERNAL | XSOAR | User | NONE | ***Status***: NO_SLA | ***Status***: NO_SLA | 2026-06-04 10:37:45 UTC | 2026-06-08 09:56:51 UTC | False | True | False | False | Siemplify automation |

### gcb-case-tag-add

***
Add the specified tags to the cases.

#### Base Command

`gcb-case-tag-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_ids | Specify the IDs of the case to add tags. Supports comma-separated values.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| tags | Specify the tags to add to the cases. Supports comma-separated values. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.recentlyAddedTags | String | The list of recently added tags. |

#### Command example

```!gcb-case-tag-add case_ids=1001,1002 tags=malware,phishing```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": [
            {
                "caseId": "1001",
                "recentlyAddedTags": ["malware", "phishing"]
            },
            {
                "caseId": "1002",
                "recentlyAddedTags": ["malware", "phishing"]
            }
        ]
    }
}
```

#### Human Readable Output

>Tags malware, phishing successfully added to cases 1001, 1002.

### gcb-case-tag-remove

***
Remove the specified tag from a case.

#### Base Command

`gcb-case-tag-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case to remove the tag.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| tag | Specify the tag to remove from the case. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.recentlyRemovedTag | String | The tag that was recently removed from the case. |

#### Command example

```!gcb-case-tag-remove case_id=1001 tag=malware```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": {
            "caseId": "1001",
            "recentlyRemovedTag": "malware"
        }
    }
}
```

#### Human Readable Output

>Tag malware successfully removed from case 1001.

### gcb-case-priority-change

***
Change the priority of the specified cases.

#### Base Command

`gcb-case-priority-change`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_ids | Specify the IDs of the case to change priority. Supports comma-separated values.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| priority | Specify the new priority level for the cases. Possible values are: UNSPECIFIED, INFO, LOW, MEDIUM, HIGH, CRITICAL. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.priority | String | The updated priority of the Case. |

#### Command example

```!gcb-case-priority-change case_ids=1001,1002 priority=CRITICAL```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": [
            {
                "caseId": "1001",
                "priority": "CRITICAL"
            },
            {
                "caseId": "1002",
                "priority": "CRITICAL"
            }
        ]
    }
}
```

#### Human Readable Output

>Priority of cases 1001, 1002 successfully changed to CRITICAL.

### gcb-case-stage-definition-list

***
Retrieve the list of case stage definitions configured in the instance.

#### Base Command

`gcb-case-stage-definition-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseStageDefinition | Unknown | The list of the case stage definitions. |

#### Command example

```!gcb-case-stage-definition-list```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseStageDefinition": [
            "Triage",
            "Assessment",
            "Investigation"
        ]
    }
}
```

#### Human Readable Output

>Case Stage Definitions: Triage, Assessment, Investigation

### gcb-case-stage-change

***
Change the workflow stage of the specified cases.

#### Base Command

`gcb-case-stage-change`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_ids | Specify the IDs of the case to change stage. Supports comma-separated values.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| stage | Specify the new workflow stage name.<br/><br/>Note: Use gcb-case-stage-definition-list to retrieve case stage definition list. Possible values are: Triage, Incident, Investigation. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.stage | String | The updated workflow stage of the Case. |

#### Command example

```!gcb-case-stage-change case_ids=1001,1002 stage=Investigation```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": [
            {
                "caseId": "1001",
                "stage": "Investigation"
            },
            {
                "caseId": "1002",
                "stage": "Investigation"
            }
        ]
    }
}
```

#### Human Readable Output

>Stage of cases 1001, 1002 successfully changed to Investigation.

### gcb-case-reopen

***
Reopen the specified cases.

#### Base Command

`gcb-case-reopen`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_ids | Specify the IDs of the case to reopen. Supports comma-separated values.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| reopen_comment | Specify a comment explaining why the cases are being reopened. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.status | String | The status of the Case after reopening. |

#### Command example

```!gcb-case-reopen case_ids=1001,1002 reopen_comment="Reopening due to new evidence of malicious activity."```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": [
            {
                "caseId": "1001",
                "status": "OPENED"
            },
            {
                "caseId": "1002",
                "status": "OPENED"
            }
        ]
    }
}
```

#### Human Readable Output

>Cases 1001, 1002 successfully reopened.

### gcb-case-close-definition-list

***
Retrieve the list of case close definitions configured in the instance.

#### Base Command

`gcb-case-close-definition-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseCloseDefinition.name | String | The unique resource name of the Case close definition. |
| GoogleSecOps.CaseCloseDefinition.closeReason | String | The close reason of the Case close definition. |
| GoogleSecOps.CaseCloseDefinition.rootCause | String | The root cause of the Case close definition. |

#### Command example

```!gcb-case-close-definition-list```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseCloseDefinition": [
            {
                "name": "projects/my-project/locations/us/instances/my-instance/caseCloseDefinitions/1",
                "closeReason": "MAINTENANCE",
                "rootCause": "Rule under construction"
            },
            {
                "name": "projects/my-project/locations/us/instances/my-instance/caseCloseDefinitions/2",
                "closeReason": "INCONCLUSIVE",
                "rootCause": "No clear conclusion"
            },
            {
                "name": "projects/my-project/locations/us/instances/my-instance/caseCloseDefinitions/3",
                "closeReason": "NOT_MALICIOUS",
                "rootCause": "Similar case is already under investigation"
            },
            {
                "name": "projects/my-project/locations/us/instances/my-instance/caseCloseDefinitions/4",
                "closeReason": "MALICIOUS",
                "rootCause": "Irrelevant TCP/UDP port"
            }
        ]
    }
}
```

#### Human Readable Output

>| Close Reason | Root Cause |
>| --- | --- |
>| MAINTENANCE | Rule under construction |
>| INCONCLUSIVE | No clear conclusion |
>| NOT_MALICIOUS | Similar case is already under investigation |
>| MALICIOUS | Irrelevant TCP/UDP port |

### gcb-case-close

***
Close the specified cases.

#### Base Command

`gcb-case-close`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_ids | Specify the IDs of the case to close. Supports comma-separated values.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| close_reason | Specify the reason for closing the cases. Possible values are: MALICIOUS, NOT_MALICIOUS, MAINTENANCE, INCONCLUSIVE, UNKNOWN, CLOSE_REASON_UNSPECIFIED. | Required |
| root_cause | Specify the root cause description for the closure. | Required |
| close_comment | Specify a comment to add when closing the cases. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.status | String | The status of the Case after closure. |
| GoogleSecOps.Case.closureDetails.reason | String | The closure reason of the Case. |
| GoogleSecOps.Case.closureDetails.comment | String | The closure comment of the Case. |
| GoogleSecOps.Case.closureDetails.rootCause | String | The root cause provided at closure. |

#### Command example

```!gcb-case-close case_ids=1001,1002 close_reason=NOT_MALICIOUS root_cause="False positive from detection rule" close_comment="Confirmed not malicious"```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": [
            {
                "caseId": "1001",
                "status": "CLOSED",
                "closureDetails": {
                    "reason": "NOT_MALICIOUS",
                    "rootCause": "False positive",
                    "comment": "Confirmed not malicious"
                }
            },
            {
                "caseId": "1002",
                "status": "CLOSED",
                "closureDetails": {
                    "reason": "NOT_MALICIOUS",
                    "rootCause": "False positive",
                    "comment": "Confirmed not malicious"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>Cases 1001, 1002 successfully closed with reason NOT_MALICIOUS.

### gcb-case-assign

***
Assign the specified cases to a specific analyst or SOC role.

#### Base Command

`gcb-case-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_ids | Specify the IDs of the case to assign. Supports comma-separated values.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| assignee | Specify the user email address or a SOC role.<br/><br/>For SOC roles, add the @ prefix (for example, @Tier1). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.assignee | String | The resolved user ID or SOC role assigned to the Case after the operation. |

#### Command example

```!gcb-case-assign case_ids=1001,1002 assignee=@SocRole```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": [
            {
                "caseId": "1001",
                "assignee": "@SocRole"
            },
            {
                "caseId": "1002",
                "assignee": "@SocRole"
            }
        ]
    }
}
```

#### Human Readable Output

>Cases 1001, 1002 successfully assigned to @SocRole.

### gcb-case-comment-list

***
Retrieve the list of comments associated with the specified case.

#### Base Command

`gcb-case-comment-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case to retrieve comments.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| page_size | Specify the maximum number of comments to return.<br/><br/>Note: Maximum value is 1000. Default is 50. | Optional |
| page_token | Specify the page token for pagination.<br/><br/>Note: Use the next_page_token from a previous gcb-case-comment-list response. | Optional |
| sort_by | Specify the field to sort results by. Possible values are: createTime, updateTime, user, comment, deletionInvoker, favorite, alert, deleted. Default is createTime. | Optional |
| sort_order | Specify the sort direction for the results. Possible values are: Asc, Desc. Default is Desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseComment.name | String | The unique resource name of the Case comment. |
| GoogleSecOps.CaseComment.commentId | String | The ID of the Case comment. |
| GoogleSecOps.CaseComment.createTime | String | The creation time of the Case comment \(unix epoch milliseconds\). |
| GoogleSecOps.CaseComment.updateTime | String | The last update time of the Case comment \(unix epoch milliseconds\). |
| GoogleSecOps.CaseComment.user | String | User owner of the comment. |
| GoogleSecOps.CaseComment.comment | String | The text of the Case comment. |
| GoogleSecOps.CaseComment.userOwnerFullName | String | The user who created the comment. |
| GoogleSecOps.CaseComment.lastEditorFullName | String | The user who last edited the comment. |
| GoogleSecOps.CaseComment.deletedByUser | String | The user who deleted the comment. |
| GoogleSecOps.CaseComment.alertIdentifier | String | The alert associated with the comment. |
| GoogleSecOps.CaseComment.isFavorite | Boolean | Whether the comment is marked as a favorite. |
| GoogleSecOps.CaseComment.isDeleted | Boolean | Indicates if the comment has been softly deleted. |
| GoogleSecOps.CaseComment.case | String | The case associated with the comment. |
| GoogleSecOps.PageToken.command | String | The command name associated with the pagination token. |
| GoogleSecOps.PageToken.nextPageToken | String | Token to fetch the next page of case comments. |
| GoogleSecOps.PageToken.totalSize | Number | The total number of case comments available. |

#### Command example

```!gcb-case-comment-list case_id=1001```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseComment": [
            {
                "name": "projects/chronicle-mock-proj/locations/us/instances/mock-inst-uuid/cases/1001/caseComments/2001",
                "commentId": "2001",
                "createTime": "1780466772061",
                "updateTime": "1780466772061",
                "comment": "Initial assessment complete. Escalating to senior analyst.",
                "isFavorite": true,
                "alertIdentifier": "alert-mock-security-001",
                "isDeleted": false,
                "case": "1001"
            },
            {
                "name": "projects/chronicle-mock-proj/locations/us/instances/mock-inst-uuid/cases/1001/caseComments/2002",
                "commentId": "2002",
                "createTime": "1780465892736",
                "updateTime": "1780465892736",
                "user": "user-uuid-mock-12345",
                "comment": "Threat actor identified. Initiating containment measures.",
                "userOwnerFullName": "Bob Wilson",
                "lastEditorFullName": "Bob Wilson",
                "isFavorite": false,
                "isDeleted": false,
                "deletedByUser": "user-uuid-mock-12345",
                "case": "1001"
            }
        ],
        "PageToken": {
            "command": "gcb-case-comment-list",
            "nextPageToken": "mock-pagination-token",
            "totalSize": 4
        }
    }
}
```

#### Human Readable Output

>### Case Comments
>
>| Author | Comment | Create Time |
>| --- | --- | --- |
>| Automation | Initial assessment complete. Escalating to senior analyst. | 2026-06-03 06:06:12 UTC |
>| Bob Wilson | Threat actor identified. Initiating containment measures. | 2026-06-03 05:51:32 UTC |
>
>Maximum number of comments specified in page_size has been returned. To fetch the next set of comments, execute the command with the page token as `mock-pagination-token`.

### gcb-case-comment-create

***
Add a comment to the specified case.

#### Base Command

`gcb-case-comment-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case to add the comment.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| comment | Specify the comment text to add to the case. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseComment.name | String | The unique resource name of the Case comment. |
| GoogleSecOps.CaseComment.commentId | String | The ID of the Case comment. |
| GoogleSecOps.CaseComment.createTime | String | The creation time of the Case comment \(unix epoch milliseconds\). |
| GoogleSecOps.CaseComment.updateTime | String | The last update time of the Case comment \(unix epoch milliseconds\). |
| GoogleSecOps.CaseComment.user | String | User owner of the comment. |
| GoogleSecOps.CaseComment.comment | String | The text of the Case comment. |
| GoogleSecOps.CaseComment.userOwnerFullName | String | The user who created the comment. |
| GoogleSecOps.CaseComment.lastEditorFullName | String | The user who last edited the comment. |
| GoogleSecOps.CaseComment.deletedByUser | String | The user who deleted the comment. |
| GoogleSecOps.CaseComment.alertIdentifier | String | The alert associated with the comment. |
| GoogleSecOps.CaseComment.isFavorite | Boolean | Whether the comment is marked as a favorite. |
| GoogleSecOps.CaseComment.isDeleted | Boolean | Indicates if the comment has been softly deleted. |
| GoogleSecOps.CaseComment.case | String | The case associated with the comment. |

#### Command example

```!gcb-case-comment-create case_id=1001 comment="Investigated the outbound traffic. Confirmed malicious C2 communication."```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseComment": {
            "name": "projects/chronicle-mock-proj/locations/us/instances/mock-inst-uuid/cases/1001/caseComments/comment-001",
            "commentId": "comment-001",
            "createTime": "1780642722226",
            "updateTime": "1780642722226",
            "comment": "Investigated the outbound traffic. Confirmed malicious C2 communication.",
            "isFavorite": false,
            "isDeleted": false,
            "case": "1001"
        }
    }
}
```

#### Human Readable Output

>Successfully added the following comment to case "1001" at 2026-06-05 06:58:42 UTC:
>
>`Investigated the outbound traffic. Confirmed malicious C2 communication.`

### gcb-case-sla-pause

***
Pause the SLA timer for the specified case.

#### Base Command

`gcb-case-sla-pause`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case to pause the SLA timer.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| message | Specify the reason for pausing the SLA timer. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.slaStatus | String | The SLA status of the Case after the operation. |

#### Command example

```!gcb-case-sla-pause case_id=1001 message="Pausing SLA pending additional investigation."```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": {
            "caseId": "1001",
            "slaStatus": "PAUSED"
        }
    }
}
```

#### Human Readable Output

>SLA timer for case 1001 successfully paused.

### gcb-case-sla-resume

***
Resume the SLA timer for the specified case.

#### Base Command

`gcb-case-sla-resume`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case to resume the SLA timer.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Case.caseId | String | The ID of the Case. |
| GoogleSecOps.Case.slaStatus | String | The SLA status of the Case after the operation. |

#### Command example

```!gcb-case-sla-resume case_id=1001```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Case": {
            "caseId": "1001",
            "slaStatus": "SLA_EXPIRATION_STATUS_UNSPECIFIED"
        }
    }
}
```

#### Human Readable Output

>SLA timer for case 1001 successfully resumed.

### gcb-case-alert-list

***
Retrieve the list of alerts associated with the specified case.

#### Base Command

`gcb-case-alert-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case to list alerts.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| display_name | Filter alerts by display name. Supports comma-separated values. | Optional |
| priority | Filter alerts by priority. Supports comma-separated values. Possible values are: LEGACY_CASE_PRIORITY_UNSPECIFIED, UNCHANGED, INFORMATIVE, LOW, MEDIUM, HIGH, CRITICAL. | Optional |
| status | Filter alerts by status. Supports comma-separated values. Possible values are: OPEN, CLOSE, ALERT_STATUS_UNSPECIFIED. | Optional |
| product | Filter alerts by product name. Supports comma-separated values. | Optional |
| vendor | Filter alerts by vendor name. Supports comma-separated values. | Optional |
| tag | Filter alerts by tag name. Supports comma-separated values. | Optional |
| environment | Filter alerts by environment name. Supports comma-separated values. | Optional |
| source_system_name | Filter alerts by the alerting system that raised the alert. Supports comma-separated values. | Optional |
| manual | Filter alerts by whether they were created manually. Possible values are: True, False. | Optional |
| create_start_time | Filter alerts created on or after this time.<br/><br/>Note: Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 2026-05-17T14:05:44Z. | Optional |
| create_end_time | Filter alerts created on or before this time.<br/><br/>Note: Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 2026-05-17T14:05:44Z. | Optional |
| update_start_time | Filter alerts updated on or after this time.<br/><br/>Note: Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 2026-05-17T14:05:44Z. | Optional |
| update_end_time | Filter alerts updated on or before this time.<br/><br/>Note: Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 2026-05-17T14:05:44Z. | Optional |
| advanced_filter | Specify a raw AIP-160 filter string to query alerts with advanced conditions. When provided, this filter is used as-is and all other filter arguments are ignored.<br/><br/>Note: Supported filter fields: displayName, product, vendor, environment, sourceSystemName, priority, status, createTime, updateTime.<br/><br/>Example: (priority='HIGH' OR status='OPEN') AND product='DLP'. | Optional |
| filter_logic | Specify the logical operator to combine filter conditions. Possible values are: AND, OR. Default is AND. | Optional |
| page_size | Specify the maximum number of alerts to return.<br/><br/>Note: Maximum value is 1000. Default is 50. | Optional |
| page_token | Specify the page token for pagination.<br/><br/>Note: Use the next_page_token from a previous gcb-case-alert-list response. | Optional |
| sort_by | Specify the field to sort results by. Possible values are: displayName, caseId, identifier, sourceGroupingIdentifier, product, vendor, environment, ticketId, sourceSystemName, priority, status, startTime, endTime, createTime. Default is createTime. | Optional |
| sort_order | Specify the sort direction for the results. Possible values are: Asc, Desc. Default is Desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseAlert.name | String | The unique resource name of the Case Alert. |
| GoogleSecOps.CaseAlert.alertId | String | The ID of the Case Alert extracted from the resource name. |
| GoogleSecOps.CaseAlert.caseId | Number | The ID of the Case the alert belongs to. |
| GoogleSecOps.CaseAlert.identifier | String | The legacy identifier \(alert title \+ GUID\) of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceGroupingIdentifier | String | The source grouping identifier used to group related Case Alerts. |
| GoogleSecOps.CaseAlert.alertGroupIdentifier | String | The alert group identifier of the Case Alert. |
| GoogleSecOps.CaseAlert.displayName | String | The display name of the Case Alert. |
| GoogleSecOps.CaseAlert.product | String | The product associated with the Case Alert. |
| GoogleSecOps.CaseAlert.vendor | String | The vendor associated with the Case Alert. |
| GoogleSecOps.CaseAlert.environment | String | The environment of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceSystemName | String | The alerting system that raised the Case Alert. |
| GoogleSecOps.CaseAlert.sourceIdentifier | String | The source identifier \(e.g. connector ID\) of the Case Alert. |
| GoogleSecOps.CaseAlert.ruleGenerator | String | The third-party rule that triggered the Case Alert. |
| GoogleSecOps.CaseAlert.siemAlertId | String | The SIEM alert identifier of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceUrl | String | The source URL of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceRuleUrl | String | The source rule URL of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceSystemUrl | String | The source system URL of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceRuleIdentifier | String | The source rule identifier of the Case Alert. |
| GoogleSecOps.CaseAlert.ticketId | String | The ticket ID linked to the Case Alert in the integrated ticketing system. |
| GoogleSecOps.CaseAlert.additionalProperties | String | The additional connector data of the Case Alert as a JSON string. |
| GoogleSecOps.CaseAlert.priority | String | The priority of the Case Alert. |
| GoogleSecOps.CaseAlert.status | String | The status of the Case Alert. |
| GoogleSecOps.CaseAlert.manual | Boolean | Whether the Case Alert was created manually. |
| GoogleSecOps.CaseAlert.nestingDepth | Number | The nesting depth level of the Case Alert. |
| GoogleSecOps.CaseAlert.playbookStatus | String | The playbook or workflow status of the Case Alert. |
| GoogleSecOps.CaseAlert.attachedPlaybookName | String | The name of the playbook attached to the Case Alert. |
| GoogleSecOps.CaseAlert.eventCount | Number | The number of events that triggered the Case Alert. |
| GoogleSecOps.CaseAlert.playbookRunCount | Number | The number of times the first playbook was run for the Case Alert. |
| GoogleSecOps.CaseAlert.createTime | String | The creation time of the Case Alert \(unix epoch milliseconds\). |
| GoogleSecOps.CaseAlert.updateTime | String | The last update time of the Case Alert \(unix epoch milliseconds\). |
| GoogleSecOps.CaseAlert.startTime | String | The time the alert was created on the third-party system. |
| GoogleSecOps.CaseAlert.endTime | String | The time the alert was closed on the third-party system. |
| GoogleSecOps.CaseAlert.sla.expirationStatus | String | The SLA expiration status of the Case Alert. |
| GoogleSecOps.CaseAlert.sla.expirationTime | String | The SLA expiration time of the Case Alert. |
| GoogleSecOps.CaseAlert.sla.criticalExpirationTime | String | The SLA critical expiration time of the Case Alert. |
| GoogleSecOps.CaseAlert.sla.remainingTimeSinceLastPause | Number | The remaining time since the last SLA pause of the Case Alert. |
| GoogleSecOps.CaseAlert.tags.tag | String | The tag value associated with the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.reason | String | The closure reason of the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.comment | String | The closure comment of the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.rootCause | String | The root cause provided at closure of the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.closingTimeMs | String | The closure time of the Case Alert in Unix milliseconds. |
| GoogleSecOps.CaseAlert.involvedRelations.identifier | String | The identifier of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.alertIdentifier | String | The identifier of the alert the Involved Relation belongs to. |
| GoogleSecOps.CaseAlert.involvedRelations.caseId | Number | The Case ID the Involved Relation belongs to. |
| GoogleSecOps.CaseAlert.involvedRelations.relationType | String | The type of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.deviceProduct | String | The product associated with the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.deviceVendor | String | The vendor associated with the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.categoryOutcome | String | The category outcome of the Involved Relation \(e.g. Blocked, Allowed\). |
| GoogleSecOps.CaseAlert.involvedRelations.destinationPort | String | The destination port of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.eventClassId | String | The event display name of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.startTime | Date | The start time of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.endTime | Date | The end time of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.additionalProperties | String | The additional data of the Involved Relation as a JSON string. |
| GoogleSecOps.CaseAlert.involvedRelations.from.identifier | String | The identifier of the source entity of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.from.type | String | The type of the source entity of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.to.identifier | String | The identifier of the destination entity of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.to.type | String | The type of the destination entity of the Involved Relation. |
| GoogleSecOps.PageToken.command | String | The command name associated with the pagination token. |
| GoogleSecOps.PageToken.nextPageToken | String | The token to retrieve the next page of Case Alerts. |
| GoogleSecOps.PageToken.totalSize | Number | The total number of Case Alerts matching the query. |

#### Command example

```!gcb-case-alert-list case_id=1001 priority=HIGH status=OPEN sort_by=priority sort_order=Asc page_size=10```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseAlert": [
            {
                "name": "projects/chronicle-mock-proj/locations/us/instances/00000000-0000-0000-0000-000000000001/cases/1001/caseAlerts/1000001",
                "alertId": "1000001",
                "caseId": 1001,
                "identifier": "TEST ALERT_00000000-0000-0000-0000-000000000010",
                "displayName": "TEST ALERT",
                "product": "Test Product",
                "vendor": "Test Vendor",
                "environment": "Default Environment",
                "sourceSystemName": "Test Source System",
                "ruleGenerator": "Test-Alert-Rule-01",
                "sourceGroupingIdentifier": "0.0.0.1",
                "sourceIdentifier": "Test Source Identifier_00000000-0000-0000-0000-000000000011",
                "ticketId": "0.0.0.1_2026-05-10 08:00:00",
                "additionalProperties": "{\"Name\":\"TEST ALERT\",\"Type\":\"ALERT\"}",
                "priority": "HIGH",
                "status": "OPEN",
                "createTime": "1778778979232",
                "updateTime": "1779426987796",
                "startTime": "1778778979232",
                "endTime": "1779426987796",
                "playbookStatus": "COMPLETED",
                "attachedPlaybookName": "Test Playbook",
                "alertGroupIdentifier": "TEST ALERT_00000000-0000-0000-0000-000000000010",
                "eventCount": 5,
                "playbookRunCount": 1,
                "sla": {
                    "expirationTime": "1780832620238",
                    "expirationStatus": "OPEN_SLA"
                },
                "tags": [
                    {
                        "tag": "demo_1"
                    }
                ],
                "involvedRelations": [
                    {
                        "identifier": "00000000-0000-0000-0000-000000000020",
                        "alertIdentifier": "TEST ALERT_00000000-0000-0000-0000-000000000010",
                        "caseId": 1001,
                        "relationType": "ALERT",
                        "deviceProduct": "Test Product",
                        "deviceVendor": "Test Vendor",
                        "categoryOutcome": "Blocked",
                        "destinationPort": "443",
                        "eventClassId": "Test Event Class",
                        "from": {
                            "identifier": "0.0.0.1",
                            "type": "ADDRESS"
                        },
                        "to": {
                            "identifier": "test-host-01",
                            "type": "HOSTNAME"
                        }
                    }
                ]
            },
            {
                "name": "projects/chronicle-mock-proj/locations/us/instances/00000000-0000-0000-0000-000000000001/cases/1001/caseAlerts/1000002",
                "alertId": "1000002",
                "caseId": 1001,
                "identifier": "TEST ALERT 2_00000000-0000-0000-0000-000000000030",
                "displayName": "TEST ALERT 2",
                "product": "Test Product 2",
                "vendor": "Test Vendor 2",
                "environment": "Default Environment",
                "sourceSystemName": "Test Source System 2",
                "ruleGenerator": "Test-Alert-Rule-02",
                "sourceGroupingIdentifier": "0.0.0.1",
                "ticketId": "0.0.0.2_2026-05-10 07:00:00",
                "additionalProperties": "{\"Name\":\"TEST ALERT 2\",\"Type\":\"ALERT\"}",
                "priority": "MEDIUM",
                "status": "OPEN",
                "createTime": "1778778979000",
                "updateTime": "1779426987000",
                "startTime": "1778778979000",
                "endTime": "1779426987000",
                "playbookStatus": "PENDING_FOR_USER",
                "attachedPlaybookName": "Test Playbook 2",
                "alertGroupIdentifier": "TEST ALERT 2_00000000-0000-0000-0000-000000000030",
                "eventCount": 2,
                "playbookRunCount": 0,
                "sla": {
                    "expirationTime": "1779426987000",
                    "expirationStatus": "OPEN_SLA"
                }
            }
        ],
        "PageToken": {
            "command": "gcb-case-alert-list",
            "nextPageToken": "test-next-page-token",
            "totalSize": 10
        }
    }
}
```

#### Human Readable Output

>### Case Alerts List
>
>|Alert ID|Alert Name|Create Time|Priority|Status|Events Count|Alert SLA|Playbook Attached Name|Playbook Attached Status|
>|---|---|---|---|---|---|---|---|---|
>| 1000001 | TEST ALERT | 2026-05-14 17:16:19 UTC | HIGH | OPEN | 5 | ***Status***: OPEN_SLA<br/>***Expiration Time***: 2026-06-07 11:43:40 UTC | Test Playbook | COMPLETED |
>| 1000002 | TEST ALERT 2 | 2026-05-14 17:16:19 UTC | MEDIUM | OPEN | 2 | ***Status***: OPEN_SLA<br/>***Expiration Time***: 2026-05-22 05:16:27 UTC | Test Playbook 2 | PENDING_FOR_USER |
>
>Maximum number of alerts specified in page_size has been returned. To fetch the next set of alerts, execute the command with the page token as `test-next-page-token`.

### gcb-case-alert-get

***
Retrieve detailed information about a specific case alert by its ID.

#### Base Command

`gcb-case-alert-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case the alert belongs to.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert to retrieve.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseAlert.name | String | The unique resource name of the Case Alert. |
| GoogleSecOps.CaseAlert.alertId | String | The ID of the Case Alert extracted from the resource name. |
| GoogleSecOps.CaseAlert.caseId | Number | The ID of the Case the alert belongs to. |
| GoogleSecOps.CaseAlert.identifier | String | The legacy identifier \(alert title \+ GUID\) of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceGroupingIdentifier | String | The source grouping identifier used to group related Case Alerts. |
| GoogleSecOps.CaseAlert.alertGroupIdentifier | String | The alert group identifier of the Case Alert. |
| GoogleSecOps.CaseAlert.displayName | String | The display name of the Case Alert. |
| GoogleSecOps.CaseAlert.product | String | The product associated with the Case Alert. |
| GoogleSecOps.CaseAlert.vendor | String | The vendor associated with the Case Alert. |
| GoogleSecOps.CaseAlert.environment | String | The environment of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceSystemName | String | The alerting system that raised the Case Alert. |
| GoogleSecOps.CaseAlert.sourceIdentifier | String | The source identifier \(e.g. connector ID\) of the Case Alert. |
| GoogleSecOps.CaseAlert.ruleGenerator | String | The third-party rule that triggered the Case Alert. |
| GoogleSecOps.CaseAlert.siemAlertId | String | The SIEM alert identifier of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceUrl | String | The source URL of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceRuleUrl | String | The source rule URL of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceSystemUrl | String | The source system URL of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceRuleIdentifier | String | The source rule identifier of the Case Alert. |
| GoogleSecOps.CaseAlert.ticketId | String | The ticket ID linked to the Case Alert in the integrated ticketing system. |
| GoogleSecOps.CaseAlert.additionalProperties | String | The additional connector data of the Case Alert as a JSON string. |
| GoogleSecOps.CaseAlert.priority | String | The priority of the Case Alert. |
| GoogleSecOps.CaseAlert.status | String | The status of the Case Alert. |
| GoogleSecOps.CaseAlert.manual | Boolean | Whether the Case Alert was created manually. |
| GoogleSecOps.CaseAlert.nestingDepth | Number | The nesting depth level of the Case Alert. |
| GoogleSecOps.CaseAlert.playbookStatus | String | The playbook or workflow status of the Case Alert. |
| GoogleSecOps.CaseAlert.attachedPlaybookName | String | The name of the playbook attached to the Case Alert. |
| GoogleSecOps.CaseAlert.eventCount | Number | The number of events that triggered the Case Alert. |
| GoogleSecOps.CaseAlert.playbookRunCount | Number | The number of times the first playbook was run for the Case Alert. |
| GoogleSecOps.CaseAlert.createTime | String | The creation time of the Case Alert \(unix epoch milliseconds\). |
| GoogleSecOps.CaseAlert.updateTime | String | The last update time of the Case Alert \(unix epoch milliseconds\). |
| GoogleSecOps.CaseAlert.startTime | String | The time the alert was created on the third-party system. |
| GoogleSecOps.CaseAlert.endTime | String | The time the alert was closed on the third-party system. |
| GoogleSecOps.CaseAlert.sla.slaStatus | String | The SLA expiration status of the Case Alert. |
| GoogleSecOps.CaseAlert.sla.slaExpireTime | String | The SLA expiration time of the Case Alert. |
| GoogleSecOps.CaseAlert.tags.tag | String | The tag value associated with the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.reason | String | The closure reason of the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.comment | String | The closure comment of the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.rootCause | String | The root cause provided at closure of the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.closingTimeMs | String | The closure time of the Case Alert in Unix milliseconds. |
| GoogleSecOps.CaseAlert.involvedRelations.identifier | String | The identifier of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.alertIdentifier | String | The identifier of the alert the Involved Relation belongs to. |
| GoogleSecOps.CaseAlert.involvedRelations.caseId | Number | The Case ID the Involved Relation belongs to. |
| GoogleSecOps.CaseAlert.involvedRelations.relationType | String | The type of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.deviceProduct | String | The product associated with the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.deviceVendor | String | The vendor associated with the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.categoryOutcome | String | The category outcome of the Involved Relation \(e.g. Blocked, Allowed\). |
| GoogleSecOps.CaseAlert.involvedRelations.destinationPort | String | The destination port of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.eventClassId | String | The event display name of the Involved Relation \(e.g. Email Check, Data Exfiltration\). |
| GoogleSecOps.CaseAlert.involvedRelations.startTime | String | The start time of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.endTime | String | The end time of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.additionalProperties | String | The additional data of the Involved Relation as a JSON string. |
| GoogleSecOps.CaseAlert.involvedRelations.from.identifier | String | The identifier of the source entity of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.from.type | String | The type of the source entity of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.to.identifier | String | The identifier of the destination entity of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.to.type | String | The type of the destination entity of the Involved Relation. |

#### Command Example

```!gcb-case-alert-get case_id=1001 alert_id=1000001```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseAlert": {
            "name": "projects/chronicle-mock-proj/locations/us/instances/00000000-0000-0000-0000-000000000001/cases/1001/caseAlerts/1000001",
            "alertId": "1000001",
            "identifier": "TEST ALERT_00000000-0000-0000-0000-000000000010",
            "caseId": 1001,
            "createTime": "1778778979232",
            "updateTime": "1779426987796",
            "ruleGenerator": "Test-Alert-Rule-01",
            "sourceGroupingIdentifier": "0.0.0.1",
            "product": "Test Product",
            "displayName": "TEST ALERT",
            "vendor": "Test Vendor",
            "environment": "Default Environment",
            "ticketId": "0.0.0.1_2026-05-10 08:00:00",
            "sourceSystemName": "Test Source System",
            "closureDetails": {
                "reason": "NOT_MALICIOUS",
                "comment": "Testing",
                "rootCause": "False positive from detection rule",
                "closingTimeMs": "1779447705049"
            },
            "sla": {
                "expirationTime": "1780832620238",
                "expirationStatus": "OPEN_SLA"
            },
            "priority": "HIGH",
            "sourceIdentifier": "Test Source Identifier_00000000-0000-0000-0000-000000000011",
            "additionalProperties": "{\"Name\":\"TEST ALERT\",\"Type\":\"ALERT\",\"EndTime\":\"1779426987796\",\"Alert_Id\":\"0.0.0.1_2026-05-10 08:00:00\",\"TicketId\":\"0.0.0.1_2026-05-10 08:00:00\",\"DisplayId\":\"0.0.0.1_2026-05-10 08:00:00\",\"StartTime\":\"1778778979232\",\"IsArtifact\":\"False\",\"IsEnriched\":\"False\",\"IsTestCase\":\"False\",\"Description\":\"Test alert description.\",\"Environment\":\"Default Environment\",\"IsSuspicious\":\"False\",\"IsVulnerable\":\"False\",\"DataAccessScope\":null,\"IsInternalAsset\":\"False\",\"IsSkipPlaybooks\":null,\"AlertBaseEventIds\":\"00000000-0000-0000-0000-000000000012\",\"EstimatedStartTime\":\"1778778979232\"}",
            "status": "OPEN",
            "startTime": "1778778979232",
            "endTime": "1779426987796",
            "playbookStatus": "COMPLETED",
            "attachedPlaybookName": "Test Playbook",
            "alertGroupIdentifier": "TEST ALERT_00000000-0000-0000-0000-000000000010",
            "eventCount": 5,
            "playbookRunCount": 1,
            "tags": [
                {
                    "tag": "demo_1"
                },
                {
                    "tag": "demo_2"
                }
            ],
            "involvedRelations": [
                {
                    "identifier": "00000000-0000-0000-0000-000000000020",
                    "alertIdentifier": "TEST ALERT_00000000-0000-0000-0000-000000000010",
                    "caseId": 1001,
                    "relationType": "ALERT",
                    "from": {
                        "identifier": "0.0.0.1",
                        "type": "ADDRESS"
                    },
                    "to": {
                        "identifier": "test-host-01",
                        "type": "HOSTNAME"
                    },
                    "deviceProduct": "Test Product",
                    "deviceVendor": "Test Vendor",
                    "categoryOutcome": "Blocked",
                    "destinationPort": "443",
                    "eventClassId": "Test Event Class"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Case Alert Information
>
>|Alert ID|Case ID|Display Name|Status|Priority|Product|Vendor|Environment|Tags|SLA|Event Count|Alert Identifier|Alert Group Identifier|Playbook Status|Attached Playbook Name|Playbook Run Count|Create Time|Update Time|Start Time|End Time|Manual|Rule Generator|Ticket ID|Source System Name|Source Identifier|Source Grouping Identifier|Siem Alert ID|Source URL|Additional Properties|Closure Details|Involved Relations|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1000001 | 1001 | TEST ALERT | OPEN | HIGH | Test Product | Test Vendor | Default Environment | demo_1, demo_2 | ***Status***: OPEN_SLA<br/>***Expiration Time***: 2026-06-07 11:43:40 UTC | 5 | TEST ALERT_00000000-0000-0000-0000-000000000010 | TEST ALERT_00000000-0000-0000-0000-000000000010 | COMPLETED | Test Playbook | 1 | 2026-05-14 17:16:19 UTC | 2026-05-22 05:16:27 UTC | 2026-05-14 17:16:19 UTC | 2026-05-22 05:16:27 UTC | False | Test-Alert-Rule-01 | 0.0.0.1_2026-05-10 08:00:00 | Test Source System | Test Source Identifier_00000000-0000-0000-0000-000000000011 | 0.0.0.1 | 0.0.0.1_2026-05-10 08:00:00 | http://demo.com/alerts/1000001 | {"Name":"TEST ALERT","Type":"ALERT","EndTime":"1779426987796","Alert_Id":"0.0.0.1_2026-05-10 08:00:00","TicketId":"0.0.0.1_2026-05-10 08:00:00","DisplayId":"0.0.0.1_2026-05-10 08:00:00","StartTime":"1778778979232","IsArtifact":"False","IsEnriched":"False","IsTestCase":"False","Description":"Test alert description.","Environment":"Default Environment","IsSuspicious":"False","IsVulnerable":"False","DataAccessScope":null,"IsInternalAsset":"False","IsSkipPlaybooks":null,"AlertBaseEventIds":"00000000-0000-0000-0000-000000000012","EstimatedStartTime":"1778778979232"} | ***reason***: NOT_MALICIOUS<br/>***comment***: Testing<br/>***rootCause***: False positive from detection rule<br/>***closingTimeMs***: 1779447705049 | **-** ***identifier***: 00000000-0000-0000-0000-000000000020<br/> ***alertIdentifier***: TEST ALERT_00000000-0000-0000-0000-000000000010<br/> ***caseId***: 1001<br/> ***relationType***: ALERT<br/> **from**:<br/>  ***identifier***: 0.0.0.1<br/>  ***type***: ADDRESS<br/> **to**:<br/>  ***identifier***: test-host-01<br/>  ***type***: HOSTNAME<br/> ***deviceProduct***: Test Product<br/> ***deviceVendor***: Test Vendor<br/> ***categoryOutcome***: Blocked<br/> ***destinationPort***: 443<br/> ***eventClassId***: Test Event Class |

### gcb-case-alert-update

***
Update the properties of an existing case alert.

#### Base Command

`gcb-case-alert-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case the alert belongs to.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert to update.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| status | Specify the new status for the alert. Possible values are: ALERT_STATUS_UNSPECIFIED, OPEN, CLOSE. | Optional |
| priority | Specify the new priority for the alert. Possible values are: LEGACY_CASE_PRIORITY_UNSPECIFIED, UNCHANGED, INFORMATIVE, LOW, MEDIUM, HIGH, CRITICAL. | Optional |
| close_reason | Specify the reason for closing the alert.<br/><br/>Note: Required when status is CLOSE. Possible values are: MALICIOUS, NOT_MALICIOUS, MAINTENANCE, INCONCLUSIVE, UNKNOWN, CLOSE_REASON_UNSPECIFIED. | Optional |
| close_comment | Specify a comment to add when closing the alert. | Optional |
| root_cause | Specify the root cause for the alert closure.<br/><br/>Note: Required when status is CLOSE. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseAlert.name | String | The unique resource name of the Case Alert. |
| GoogleSecOps.CaseAlert.alertId | String | The ID of the Case Alert extracted from the resource name. |
| GoogleSecOps.CaseAlert.caseId | Number | The ID of the Case the alert belongs to. |
| GoogleSecOps.CaseAlert.identifier | String | The legacy identifier \(alert title \+ GUID\) of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceGroupingIdentifier | String | The source grouping identifier used to group related Case Alerts. |
| GoogleSecOps.CaseAlert.alertGroupIdentifier | String | The alert group identifier of the Case Alert. |
| GoogleSecOps.CaseAlert.displayName | String | The display name of the Case Alert. |
| GoogleSecOps.CaseAlert.product | String | The product associated with the Case Alert. |
| GoogleSecOps.CaseAlert.vendor | String | The vendor associated with the Case Alert. |
| GoogleSecOps.CaseAlert.environment | String | The environment of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceSystemName | String | The alerting system that raised the Case Alert. |
| GoogleSecOps.CaseAlert.sourceIdentifier | String | The source identifier \(e.g. connector ID\) of the Case Alert. |
| GoogleSecOps.CaseAlert.ruleGenerator | String | The third-party rule that triggered the Case Alert. |
| GoogleSecOps.CaseAlert.siemAlertId | String | The SIEM alert identifier of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceUrl | String | The source URL of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceRuleUrl | String | The source rule URL of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceSystemUrl | String | The source system URL of the Case Alert. |
| GoogleSecOps.CaseAlert.sourceRuleIdentifier | String | The source rule identifier of the Case Alert. |
| GoogleSecOps.CaseAlert.ticketId | String | The ticket ID linked to the Case Alert in the integrated ticketing system. |
| GoogleSecOps.CaseAlert.additionalProperties | String | The additional connector data of the Case Alert as a JSON string. |
| GoogleSecOps.CaseAlert.priority | String | The priority of the Case Alert. |
| GoogleSecOps.CaseAlert.status | String | The status of the Case Alert. |
| GoogleSecOps.CaseAlert.manual | Boolean | Whether the Case Alert was created manually. |
| GoogleSecOps.CaseAlert.nestingDepth | Number | The nesting depth level of the Case Alert. |
| GoogleSecOps.CaseAlert.playbookStatus | String | The playbook or workflow status of the Case Alert. |
| GoogleSecOps.CaseAlert.attachedPlaybookName | String | The name of the playbook attached to the Case Alert. |
| GoogleSecOps.CaseAlert.eventCount | Number | The number of events that triggered the Case Alert. |
| GoogleSecOps.CaseAlert.playbookRunCount | Number | The number of times the first playbook was run for the Case Alert. |
| GoogleSecOps.CaseAlert.createTime | String | The creation time of the Case Alert \(unix epoch milliseconds\). |
| GoogleSecOps.CaseAlert.updateTime | String | The last update time of the Case Alert \(unix epoch milliseconds\). |
| GoogleSecOps.CaseAlert.startTime | String | The time the alert was created on the third-party system. |
| GoogleSecOps.CaseAlert.endTime | String | The time the alert was closed on the third-party system. |
| GoogleSecOps.CaseAlert.sla.slaStatus | String | The SLA expiration status of the Case Alert. |
| GoogleSecOps.CaseAlert.sla.slaExpireTime | String | The SLA expiration time of the Case Alert. |
| GoogleSecOps.CaseAlert.tags.tag | String | The tag value associated with the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.reason | String | The closure reason of the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.comment | String | The closure comment of the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.rootCause | String | The root cause provided at closure of the Case Alert. |
| GoogleSecOps.CaseAlert.closureDetails.closingTimeMs | String | The closure time of the Case Alert in Unix milliseconds. |
| GoogleSecOps.CaseAlert.involvedRelations.identifier | String | The identifier of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.alertIdentifier | String | The identifier of the alert the Involved Relation belongs to. |
| GoogleSecOps.CaseAlert.involvedRelations.caseId | Number | The Case ID the Involved Relation belongs to. |
| GoogleSecOps.CaseAlert.involvedRelations.relationType | String | The type of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.deviceProduct | String | The product associated with the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.deviceVendor | String | The vendor associated with the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.categoryOutcome | String | The category outcome of the Involved Relation \(e.g. Blocked, Allowed\). |
| GoogleSecOps.CaseAlert.involvedRelations.destinationPort | String | The destination port of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.eventClassId | String | The event display name of the Involved Relation \(e.g. Email Check, Data Exfiltration\). |
| GoogleSecOps.CaseAlert.involvedRelations.startTime | String | The start time of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.endTime | String | The end time of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.additionalProperties | String | The additional data of the Involved Relation as a JSON string. |
| GoogleSecOps.CaseAlert.involvedRelations.from.identifier | String | The identifier of the source entity of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.from.type | String | The type of the source entity of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.to.identifier | String | The identifier of the destination entity of the Involved Relation. |
| GoogleSecOps.CaseAlert.involvedRelations.to.type | String | The type of the destination entity of the Involved Relation. |

#### Command example

```!gcb-case-alert-update case_id=1001 alert_id=1000001 status=CLOSE priority=HIGH close_reason=NOT_MALICIOUS close_comment="Reviewed and confirmed as false positive." root_cause="Misconfigured DLP policy"```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseAlert": {
            "alertId": "1000001",
            "identifier": "TEST ALERT_00000000-0000-0000-0000-000000000010",
            "caseId": 1001,
            "createTime": "1778778979232",
            "updateTime": "1779426987796",
            "ruleGenerator": "Test-Alert-Rule-01",
            "sourceGroupingIdentifier": "0.0.0.1",
            "product": "Test Product",
            "displayName": "TEST ALERT",
            "vendor": "Test Vendor",
            "environment": "Default Environment",
            "ticketId": "0.0.0.1_2026-05-10 08:00:00",
            "sourceSystemName": "Test Source System",
            "closureDetails": {
                "reason": "NOT_MALICIOUS",
                "comment": "Reviewed and confirmed as false positive.",
                "rootCause": "Misconfigured DLP policy",
                "closingTimeMs": "1779447705049"
            },
            "sla": {
                "expirationTime": "1780832620238",
                "expirationStatus": "OPEN_SLA"
            },
            "priority": "HIGH",
            "additionalProperties": "{\"Name\":\"TEST ALERT\",\"Type\":\"ALERT\"}",
            "status": "CLOSE",
            "startTime": "1778778979232",
            "endTime": "1779426987796",
            "alertGroupIdentifier": "TEST ALERT_00000000-0000-0000-0000-000000000010"
        }
    }
}
```

#### Human Readable Output

>### Updated Case Alert Information
>
>|Alert ID|Case ID|Display Name|Status|Priority|Product|Vendor|Environment|SLA|Alert Identifier|Alert Group Identifier|Create Time|Update Time|Start Time|End Time|Manual|Rule Generator|Ticket ID|Source System Name|Source Grouping Identifier|Additional Properties|Closure Details|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1000001 | 1001 | TEST ALERT | CLOSE | HIGH | Test Product | Test Vendor | Default Environment | ***Status***: OPEN_SLA<br/>***Expiration Time***: 2026-06-07 11:43:40 UTC | TEST ALERT_00000000-0000-0000-0000-000000000010 | TEST ALERT_00000000-0000-0000-0000-000000000010 | 2026-05-14 17:16:19 UTC | 2026-05-22 05:16:27 UTC | 2026-05-14 17:16:19 UTC | 2026-05-22 05:16:27 UTC | False | Test-Alert-Rule-01 | 0.0.0.1_2026-05-10 08:00:00 | Test Source System | 0.0.0.1 | {"Name":"TEST ALERT","Type":"ALERT"} | ***reason***: NOT_MALICIOUS<br/>***comment***: Reviewed and confirmed as false positive.<br/>***rootCause***: Misconfigured DLP policy<br/>***closingTimeMs***: 1779447705049 |

### gcb-case-alert-tag-add

***
Add a tag to a case alert.

#### Base Command

`gcb-case-alert-tag-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case the alert belongs to.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert to add a tag.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| tag | Specify the tag to add to the alert. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseAlert.alertId | String | The ID of the Case Alert. |
| GoogleSecOps.CaseAlert.caseId | Number | The ID of the Case the alert belongs to. |
| GoogleSecOps.CaseAlert.recentlyAddedTag | String | The recently added tag. |

#### Command example

```!gcb-case-alert-tag-add case_id=1001 alert_id=1142656 tag=insider-threat```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseAlert": {
            "alertId": "1142656",
            "caseId": 1001,
            "recentlyAddedTag": "insider-threat"
        }
    }
}
```

#### Human Readable Output

>Tag insider-threat successfully added to alert 1142656.

### gcb-case-alert-tag-remove

***
Remove a tag from a case alert.

#### Base Command

`gcb-case-alert-tag-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case the alert belongs to.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert to remove a tag.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| tag | Specify the tag to remove from the alert. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseAlert.alertId | String | The ID of the Case Alert. |
| GoogleSecOps.CaseAlert.caseId | Number | The ID of the Case the alert belongs to. |
| GoogleSecOps.CaseAlert.recentlyRemovedTag | String | The tag that was recently removed from the case alert. |

#### Command example

```!gcb-case-alert-tag-remove case_id=1001 alert_id=1142656 tag=insider-threat```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseAlert": {
            "alertId": "1142656",
            "caseId": 1001,
            "recentlyRemovedTag": "insider-threat"
        }
    }
}
```

#### Human Readable Output

>Tag insider-threat successfully removed from alert 1142656.

### gcb-case-alert-move

***
Move a case alert to a different case.

Note: Both source and destination cases must be open.

#### Base Command

`gcb-case-alert-move`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the source case.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert to move.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| destination_case_id | Specify the destination case ID to move the alert to.<br/><br/>Note: Use gcb-case-list to retrieve destination case ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseAlert.alertId | String | The ID of the Case Alert. |
| GoogleSecOps.CaseAlert.caseId | Number | The Case ID the alert was moved to. |

#### Command example

```!gcb-case-alert-move case_id=1001 alert_id=1142656 destination_case_id=1005```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseAlert": {
            "alertId": "1142656",
            "caseId": 1005
        }
    }
}
```

#### Human Readable Output

>Successfully moved Alert `1142656` to Case `1005`.

### gcb-case-alert-sla-pause

***
Pause the SLA timer for the specified case alert.

#### Base Command

`gcb-case-alert-sla-pause`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case the alert belongs to.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert to pause the SLA timer.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| message | Specify the reason for pausing the SLA timer. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseAlert.alertId | String | The ID of the Case Alert. |
| GoogleSecOps.CaseAlert.caseId | Number | The ID of the Case the alert belongs to. |
| GoogleSecOps.CaseAlert.slaExpirationStatus | String | The SLA expiration status of the Case Alert after the operation. |

#### Command example

```!gcb-case-alert-sla-pause case_id=1001 alert_id=1142656 message="Pausing SLA pending additional investigation."```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseAlert": {
            "alertId": "1142656",
            "caseId": "1001",
            "slaExpirationStatus": "PAUSED"
        }
    }
}
```

#### Human Readable Output

>SLA timer for alert 1142656 successfully paused.

### gcb-case-alert-sla-resume

***
Resume the SLA timer for the specified case alert.

#### Base Command

`gcb-case-alert-sla-resume`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case the alert belongs to.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert to resume the SLA timer.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseAlert.alertId | String | The ID of the Case Alert. |
| GoogleSecOps.CaseAlert.caseId | Number | The ID of the Case the alert belongs to. |
| GoogleSecOps.CaseAlert.slaExpirationStatus | String | The SLA expiration status of the Case Alert after the operation. |

#### Command example

```!gcb-case-alert-sla-resume case_id=1001 alert_id=1142656```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseAlert": {
            "alertId": "1142656",
            "caseId": "1001",
            "slaExpirationStatus": "SLA_EXPIRATION_STATUS_UNSPECIFIED"
        }
    }
}
```

#### Human Readable Output

>SLA timer for alert 1142656 successfully resumed.

### gcb-case-alert-sla-set

***
Set the SLA parameters for a case alert.

Note: When critical_time is specified, total_time must be greater than critical_time.

#### Base Command

`gcb-case-alert-sla-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case the alert belongs to.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert to set the SLA.<br/><br/>Note: The alert must be open. Use gcb-case-alert-list to retrieve alert ID. | Required |
| total_time | Specify the total SLA duration.<br/><br/>Note: Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. For example: 2 weeks, 01 May 2026, 2026-05-17T14:05:44Z. | Required |
| critical_time | Specify the critical SLA threshold.<br/><br/>Note: Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ. For example: 2 weeks, 01 May 2026, 2026-05-17T14:05:44Z. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.CaseAlert.alertId | String | The ID of the Case Alert. |
| GoogleSecOps.CaseAlert.caseId | Number | The ID of the Case the alert belongs to. |
| GoogleSecOps.CaseAlert.slaExpirationTime | String | The SLA expiration time of the Case Alert \(epoch ms\). |
| GoogleSecOps.CaseAlert.slaCriticalExpirationTime | String | The SLA critical expiration time of the Case Alert \(epoch ms\). |

#### Command example

```!gcb-case-alert-sla-set case_id=1001 alert_id=1142656 total_time="2 days" critical_time="1 day"```

#### Context Example

```json
{
    "GoogleSecOps": {
        "CaseAlert": {
            "alertId": "1142656",
            "caseId": "1001",
            "slaExpirationTime": "1746266400000",
            "slaCriticalExpirationTime": "1746180000000"
        }
    }
}
```

#### Human Readable Output

>SLA for Alert `1142656` successfully set.

***

### gcb-case-alert-recommendation-create

***
Initiate an asynchronous AI recommendation for a case alert.

#### Base Command

`gcb-case-alert-recommendation-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case the alert belongs to.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert to generate a recommendation.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.AlertRecommendation.parent | String | The resource name of the Case Alert the recommendation belongs to. |
| GoogleSecOps.AlertRecommendation.recommendationId | String | The ID of the created recommendation. |

#### Command example

```!gcb-case-alert-recommendation-create case_id=1001 alert_id=1000001```

#### Context Example

```json
{
    "GoogleSecOps": {
        "AlertRecommendation": {
            "recommendationId": "00000000-0000-0000-0000-000000000001"
        }
    }
}
```

#### Human Readable Output

>Successfully created the recommendation for the alert 1000001.
>
>Recommendation ID: 00000000-0000-0000-0000-000000000001

### gcb-case-alert-recommendation-fetch

***
Fetch a previously generated AI recommendation for a case alert.

#### Base Command

`gcb-case-alert-recommendation-fetch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case the alert belongs to.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| recommendation_id | Specify the recommendation ID returned by gcb-case-alert-recommendation-create command. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.AlertRecommendation.parent | String | The resource name of the Case Alert the recommendation belongs to. |
| GoogleSecOps.AlertRecommendation.recommendationId | String | The ID of the recommendation. |
| GoogleSecOps.AlertRecommendation.recommendation | String | The AI-generated recommendation text for the Case Alert. |
| GoogleSecOps.AlertRecommendation.alertIdentifierToCaseId | Unknown | Mapping of alert identifiers to their associated Case IDs. |
| GoogleSecOps.AlertRecommendation.marketplaceActionsTriggeredManually | Unknown | List of marketplace actions that were manually triggered on the alert. |
| GoogleSecOps.AlertRecommendation.state | String | The current state of the recommendation generation. |

#### Command example

```!gcb-case-alert-recommendation-fetch case_id=1001 recommendation_id=00000000-0000-0000-0000-000000001000```

#### Context Example

```json
{
    "GoogleSecOps": {
        "AlertRecommendation": {
            "recommendationId": "00000000-0000-0000-0000-000000001000",
            "recommendation": "*Step 1: Closure Recommendation*\n\nClose the alert as \"Malicious\".",
            "alertIdentifierToCaseId": {
                "sample_alert_00000000-0000-0000-0000-000000000001": 100001,
                "sample_alert_00000000-0000-0000-0000-000000000002": 100002
            },
            "marketplaceActionsTriggeredManually": [
                "Enrich Web Properties",
                "Enrich IPs"
            ],
            "state": "SUCCEEDED"
        }
    }
}
```

#### Human Readable Output

> ### Alert Recommendation
>
> ***
>
> **State:** SUCCEEDED
>
> ***
>
> **Recommendation:**
> *Step 1: Closure Recommendation*
>
> Close the alert as "Malicious".
>
> ***
>
> **Alert Identifier To Case ID:**
>
> - `sample_alert_00000000-0000-0000-0000-000000000001`: 100001
> - `sample_alert_00000000-0000-0000-0000-000000000002`: 100002
>
> ***
>
> **Marketplace Actions Triggered Manually:** Enrich Web Properties, Enrich IPs

### gcb-case-alert-customfield-list

***
Retrieve the list of custom field values associated with a case alert.

#### Base Command

`gcb-case-alert-customfield-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case the alert belongs to.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert to list custom field values.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| page_size | Specify the maximum number of custom field values to return.<br/><br/>Note: Maximum value is 1000. Default is 50. | Optional |
| page_token | Specify the page token for pagination.<br/><br/>Note: Use the next_page_token from a previous gcb-case-alert-customfield-list response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.AlertCustomFieldValue.name | String | The unique resource name of the Custom Field Value. |
| GoogleSecOps.AlertCustomFieldValue.customFieldId | String | The ID of the parent Custom Field. |
| GoogleSecOps.AlertCustomFieldValue.displayName | String | The display name of the Custom Field resolved from the custom field ID. |
| GoogleSecOps.AlertCustomFieldValue.scope | String | The scope of the Custom Field Value. |
| GoogleSecOps.AlertCustomFieldValue.scopeId | String | The identifier of the scope \(case or alert\) this value references. |
| GoogleSecOps.AlertCustomFieldValue.values | Unknown | The value\(s\) for the Custom Field. |
| GoogleSecOps.AlertCustomFieldValue.valuesSearchText | String | The concatenated search text for all values of the Custom Field. |
| GoogleSecOps.PageToken.command | String | The command name for which the page token applies. |
| GoogleSecOps.PageToken.nextPageToken | String | The token to retrieve the next page of Custom Field Values. |
| GoogleSecOps.PageToken.totalSize | Number | The total number of Custom Field Values available. |

#### Command example

```!gcb-case-alert-customfield-list case_id=1001 alert_id=2001```

#### Context Example

```json
{
    "GoogleSecOps": {
        "AlertCustomFieldValue": [
            {
                "customFieldId": "1",
                "displayName": "Ticket Priority",
                "scope": "ALERT",
                "values": [
                    "High"
                ],
                "valuesSearchText": "High"
            },
            {
                "customFieldId": "2",
                "displayName": "Escalation Required",
                "scope": "ALERT",
                "values": [
                    "Yes"
                ],
                "valuesSearchText": "Yes"
            },
            {
                "customFieldId": "3",
                "displayName": "Affected Systems",
                "scope": "ALERT",
                "values": [
                    "Web Server",
                    "Database"
                ],
                "valuesSearchText": "Web Server Database"
            }
        ],
        "PageToken": {
            "command": "gcb-case-alert-customfield-list",
            "nextPageToken": "test-next-page-token",
            "totalSize": 10
        }
    }
}
```

#### Human Readable Output

>### Case Alert Custom Field Values
>
>|Custom Field ID|Display Name|Values|Values Search Text|
>|---|---|---|---|
>| 1 | Ticket Priority | High | High |
>| 2 | Escalation Required | Yes | Yes |
>| 3 | Affected Systems | Web Server, Database | Web Server Database |
>
>Maximum number of custom field values specified in page_size has been returned. To fetch the next set of custom field values, execute the command with the page token as `test-next-page-token`.

### gcb-case-alert-entity-list

***
Retrieve the list of entities associated with a case alert.

#### Base Command

`gcb-case-alert-entity-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert to list entities.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| page_size | Specify the maximum number of entities to return.<br/><br/>Note: Maximum value is 1000. Default is 50. | Optional |
| page_token | Specify the page token for pagination.<br/><br/>Note: Use the next_page_token from a previous gcb-case-alert-entity-list response. | Optional |
| entity_type | Filter entities by type. Supports comma-separated values. Possible values are: ADDRESS, HOSTNAME, PROCESS, USB. | Optional |
| suspicious | Filter entities by suspicious status. Possible values are: true, false. | Optional |
| internal | Filter entities by internal status. Possible values are: true, false. | Optional |
| attacker | Filter entities by attacker designation. Possible values are: true, false. | Optional |
| pivot | Filter entities by pivot designation. Possible values are: true, false. | Optional |
| enriched | Filter entities by enrichment status. Possible values are: true, false. | Optional |
| artifact | Filter entities by artifact flag. Possible values are: true, false. | Optional |
| vulnerable | Filter entities by vulnerable flag. Possible values are: true, false. | Optional |
| manually_created | Filter entities by manually created flag. Possible values are: true, false. | Optional |
| threat_source | Filter entities by threat source. Supports comma-separated values. | Optional |
| operating_system | Filter entities by operating system. Supports comma-separated values. | Optional |
| network_title | Filter entities by network name. Supports comma-separated values. | Optional |
| network_priority | Filter entities by network priority (integer values). Supports comma-separated values. | Optional |
| environment | Filter entities by environment. Supports comma-separated values. | Optional |
| advanced_filter | Specify a raw filter expression to query entities with advanced conditions. When provided, this filter is used as-is and all other filter arguments are ignored.<br/><br/>Note: Supported filter fields: type, suspicious, internal, attacker, pivot, enriched, artifact, vulnerable, manuallyCreated, threatSource, operatingSystem, networkTitle, networkPriority, environment, fields.<br/><br/>Example: type='ADDRESS' AND suspicious=true AND internal=false. | Optional |
| sort_by | Specify the field to sort results by. Possible values are: id, entityType, suspicious, internal, attacker, pivot, enriched, artifact, vulnerable, manuallyCreated, threatSource, operatingSystem, networkTitle, networkPriority, environment. Default is id. | Optional |
| sort_order | Specify the sort direction for the results. Possible values are: Asc, Desc. Default is Desc. | Optional |
| filter_logic | Specify the logical operator to combine filter conditions. Possible values are: AND, OR. Default is AND. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.AlertEntity.id | String | The immutable identifier of the Involved Entity. |
| GoogleSecOps.AlertEntity.identifier | String | The identifier name of the Involved Entity. |
| GoogleSecOps.AlertEntity.type | String | The type of the Involved Entity. |
| GoogleSecOps.AlertEntity.caseId | Number | The Case ID the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.alertIdentifier | String | The alert identifier the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.environment | String | The environment of the Involved Entity. |
| GoogleSecOps.AlertEntity.threatSource | String | The threat source associated with the Involved Entity. |
| GoogleSecOps.AlertEntity.operatingSystem | String | The operating system of the Involved Entity. |
| GoogleSecOps.AlertEntity.networkTitle | String | The network name related to the Involved Entity. |
| GoogleSecOps.AlertEntity.networkPriority | Number | The network priority of the Involved Entity. |
| GoogleSecOps.AlertEntity.entityUri | String | The full URL of the Involved Entity in the source system. |
| GoogleSecOps.AlertEntity.sourceSystemUri | String | The source system URI link of the Involved Entity. |
| GoogleSecOps.AlertEntity.additionalProperties | String | The additional properties of the Involved Entity as a JSON string. |
| GoogleSecOps.AlertEntity.suspicious | Boolean | Whether the Involved Entity is considered suspicious. |
| GoogleSecOps.AlertEntity.internal | Boolean | Whether the Involved Entity is internal. |
| GoogleSecOps.AlertEntity.attacker | Boolean | Whether the Involved Entity represents an attacker. |
| GoogleSecOps.AlertEntity.pivot | Boolean | Whether the Involved Entity is a pivot entity common to multiple cases. |
| GoogleSecOps.AlertEntity.manuallyCreated | Boolean | Whether the Involved Entity was added manually. |
| GoogleSecOps.AlertEntity.enriched | Boolean | Whether the Involved Entity has been enriched by an external action. |
| GoogleSecOps.AlertEntity.artifact | Boolean | Whether the Involved Entity is an artifact. |
| GoogleSecOps.AlertEntity.vulnerable | Boolean | Whether the Involved Entity is vulnerable. |
| GoogleSecOps.AlertEntity.fields.displayName | String | The display name of the context group of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.highlighted | Boolean | Whether the context group of the Involved Entity is highlighted. |
| GoogleSecOps.AlertEntity.fields.hidden | Boolean | Whether the context group of the Involved Entity is hidden. |
| GoogleSecOps.AlertEntity.fields.items.name | String | The property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.originalName | String | The original property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.value | String | The value of the context group item of the Involved Entity. |
| GoogleSecOps.PageToken.command | String | The command name associated with the pagination token. |
| GoogleSecOps.PageToken.nextPageToken | String | Token to fetch the next page of alert entities. |
| GoogleSecOps.PageToken.totalSize | Number | The total number of alert entities available. |

#### Command example

```!gcb-case-alert-entity-list case_id=306082 alert_id=1001```

#### Context Example

```json
{
    "GoogleSecOps": {
        "AlertEntity": [
            {
                "id": "376359",
                "type": "ADDRESS",
                "suspicious": true,
                "internal": true,
                "networkPriority": 0,
                "attacker": false,
                "pivot": false,
                "environment": "Default Environment",
                "manuallyCreated": false,
                "additionalProperties": "{\"Type\":\"ADDRESS\",\"IsArtifact\":\"False\",\"IsEnriched\":\"False\",\"IsVulnerable\":\"False\",\"IsInternalAsset\":\"True\",\"OriginalIdentifier\":\"999.999.999.999\"}",
                "enriched": false,
                "artifact": false,
                "vulnerable": false,
                "entityUri": "/entity?indicator=999.999.999.999&type=ipAddress",
                "fields": [
                    {
                        "displayName": "Default",
                        "highlighted": false,
                        "hidden": false,
                        "items": [
                            {"name": "Network_Priority", "originalName": "Network_Priority", "value": "0"},
                            {"name": "IsSuspicious", "originalName": "IsSuspicious", "value": "True"}
                        ]
                    },
                    {
                        "displayName": "Entity",
                        "highlighted": false,
                        "hidden": false,
                        "items": [
                            {"name": "Is Pivot", "originalName": "IsPivot", "value": "False"}
                        ]
                    }
                ],
                "alertIdentifier": "Testing Alert_62923d4f-05f0-47bf-9290-d0c94406e775",
                "caseId": 306082,
                "identifier": "999.999.999.999"
            },
            {
                "id": "376358",
                "type": "ADDRESS",
                "suspicious": false,
                "internal": false,
                "networkPriority": 0,
                "attacker": false,
                "pivot": false,
                "environment": "Default Environment",
                "manuallyCreated": false,
                "additionalProperties": "{\"Type\":\"ADDRESS\",\"IsArtifact\":\"False\",\"IsEnriched\":\"True\",\"Censys_ports\":\"53, 443, 853\",\"IsVulnerable\":\"False\",\"IsInternalAsset\":\"False\",\"OriginalIdentifier\":\"8.8.8.8\"}",
                "enriched": true,
                "artifact": false,
                "vulnerable": false,
                "entityUri": "/entity?indicator=8.8.8.8&type=ipAddress",
                "fields": [
                    {
                        "displayName": "Default",
                        "highlighted": false,
                        "hidden": false,
                        "items": [
                            {"name": "Network_Priority", "originalName": "Network_Priority", "value": "0"},
                            {"name": "IsSuspicious", "originalName": "IsSuspicious", "value": "False"}
                        ]
                    },
                    {
                        "displayName": "Entity",
                        "highlighted": false,
                        "hidden": false,
                        "items": [
                            {"name": "Is Pivot", "originalName": "IsPivot", "value": "False"}
                        ]
                    }
                ],
                "alertIdentifier": "Testing Alert_62923d4f-05f0-47bf-9290-d0c94406e775",
                "caseId": 306082,
                "identifier": "8.8.8.8"
            }
        ]
    }
}
```

#### Human Readable Output

>### Alert Entities List
>
>|ID|Identifier|Type|Environment|Suspicious|Internal|Attacker|Pivot|Enriched|Artifact|Vulnerable|Manually Created|Network Priority|Entity URI|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 376359 | 999.999.999.999 | ADDRESS | Default Environment | True | True | False | False | False | False | False | False | 0 | /entity?indicator=999.999.999.999&type=ipAddress |
>| 376358 | 8.8.8.8 | ADDRESS | Default Environment | False | False | False | False | True | False | False | False | 0 | /entity?indicator=8.8.8.8&type=ipAddress |

### gcb-case-alert-entity-get

***
Retrieve detailed information about a specific involved entity in a case alert.

#### Base Command

`gcb-case-alert-entity-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| entity_id | Specify the ID of the involved entity to retrieve.<br/><br/>Note: Use gcb-case-alert-entity-list to retrieve entity ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.AlertEntity.id | String | The immutable identifier of the Involved Entity. |
| GoogleSecOps.AlertEntity.identifier | String | The identifier name of the Involved Entity. |
| GoogleSecOps.AlertEntity.type | String | The type of the Involved Entity. |
| GoogleSecOps.AlertEntity.alertId | String | The Alert ID the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.caseId | Number | The Case ID the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.alertIdentifier | String | The alert identifier the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.environment | String | The environment of the Involved Entity. |
| GoogleSecOps.AlertEntity.threatSource | String | The threat source associated with the Involved Entity. |
| GoogleSecOps.AlertEntity.operatingSystem | String | The operating system of the Involved Entity. |
| GoogleSecOps.AlertEntity.networkTitle | String | The network name related to the Involved Entity. |
| GoogleSecOps.AlertEntity.networkPriority | Number | The network priority of the Involved Entity. |
| GoogleSecOps.AlertEntity.entityUri | String | The full URL of the Involved Entity in the source system. |
| GoogleSecOps.AlertEntity.sourceSystemUri | String | The source system URI link of the Involved Entity. |
| GoogleSecOps.AlertEntity.additionalProperties | String | The additional properties of the Involved Entity as a JSON string. |
| GoogleSecOps.AlertEntity.suspicious | Boolean | Whether the Involved Entity is considered suspicious. |
| GoogleSecOps.AlertEntity.internal | Boolean | Whether the Involved Entity is internal. |
| GoogleSecOps.AlertEntity.attacker | Boolean | Whether the Involved Entity represents an attacker. |
| GoogleSecOps.AlertEntity.pivot | Boolean | Whether the Involved Entity is a pivot entity common to multiple cases. |
| GoogleSecOps.AlertEntity.manuallyCreated | Boolean | Whether the Involved Entity was added manually. |
| GoogleSecOps.AlertEntity.enriched | Boolean | Whether the Involved Entity has been enriched by an external action. |
| GoogleSecOps.AlertEntity.artifact | Boolean | Whether the Involved Entity is an artifact. |
| GoogleSecOps.AlertEntity.vulnerable | Boolean | Whether the Involved Entity is vulnerable. |
| GoogleSecOps.AlertEntity.fields.displayName | String | The display name of the context group of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.highlighted | Boolean | Whether the context group of the Involved Entity is highlighted. |
| GoogleSecOps.AlertEntity.fields.hidden | Boolean | Whether the context group of the Involved Entity is hidden. |
| GoogleSecOps.AlertEntity.fields.items.name | String | The property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.originalName | String | The original property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.value | String | The value of the context group item of the Involved Entity. |

#### Command example

```!gcb-case-alert-entity-get case_id=306082 alert_id=1001 entity_id=376359```

#### Context Example

```json
{
    "GoogleSecOps": {
        "AlertEntity": {
            "id": "376359",
            "type": "ADDRESS",
            "suspicious": false,
            "internal": false,
            "networkPriority": 0,
            "attacker": false,
            "pivot": false,
            "environment": "Default Environment",
            "manuallyCreated": false,
            "additionalProperties": "{\"Type\":\"ADDRESS\",\"IsArtifact\":\"False\",\"IsEnriched\":\"False\",\"IsVulnerable\":\"False\",\"IsInternalAsset\":\"False\",\"OriginalIdentifier\":\"999.999.999.999\"}",
            "enriched": false,
            "artifact": false,
            "vulnerable": false,
            "entityUri": "/entity?indicator=999.999.999.999&type=ipAddress",
            "fields": [
                {
                    "displayName": "Default",
                    "highlighted": false,
                    "hidden": false,
                    "items": [
                        {
                            "name": "Network_Priority",
                            "originalName": "Network_Priority",
                            "value": "0"
                        },
                        {
                            "name": "IsSuspicious",
                            "originalName": "IsSuspicious",
                            "value": "False"
                        },
                        {
                            "name": "IsAttacker",
                            "originalName": "IsAttacker",
                            "value": "False"
                        },
                        {
                            "name": "IsManuallyCreated",
                            "originalName": "IsManuallyCreated",
                            "value": "False"
                        },
                        {
                            "name": "Environment",
                            "originalName": "Environment",
                            "value": "Default Environment"
                        },
                        {
                            "name": "Alert_Id",
                            "originalName": "Alert_Id",
                            "value": "Testing Alert_62923d4f-05f0-47bf-9290-d0c94406e775"
                        },
                        {
                            "name": "Type",
                            "originalName": "Type",
                            "value": "ADDRESS"
                        },
                        {
                            "name": "IsArtifact",
                            "originalName": "IsArtifact",
                            "value": "False"
                        },
                        {
                            "name": "IsEnriched",
                            "originalName": "IsEnriched",
                            "value": "False"
                        },
                        {
                            "name": "IsVulnerable",
                            "originalName": "IsVulnerable",
                            "value": "False"
                        },
                        {
                            "name": "IsInternalAsset",
                            "originalName": "IsInternalAsset",
                            "value": "False"
                        },
                        {
                            "name": "OriginalIdentifier",
                            "originalName": "OriginalIdentifier",
                            "value": "999.999.999.999"
                        }
                    ]
                },
                {
                    "displayName": "Entity",
                    "highlighted": false,
                    "hidden": false,
                    "items": [
                        {
                            "name": "Is Pivot",
                            "originalName": "IsPivot",
                            "value": "False"
                        }
                    ]
                }
            ],
            "alertIdentifier": "Testing Alert_62923d4f-05f0-47bf-9290-d0c94406e775",
            "caseId": 306082,
            "alertId": "1001",
            "identifier": "999.999.999.999"
        }
    }
}
```

#### Human Readable Output

>### Entity Information
>
>|ID|Identifier|Alert ID|Case ID|Alert Identifier|Type|Environment|Suspicious|Internal|Attacker|Pivot|Enriched|Artifact|Vulnerable|Manually Created|Network Priority|Entity URI|Additional Properties|Fields|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 376359 | 999.999.999.999 | 1001 | 306082 | Testing Alert_62923d4f-05f0-47bf-9290-d0c94406e775 | ADDRESS | Default Environment | False | False | False | False | False | False | False | False | 0 | /entity?indicator=999.999.999.999&type=ipAddress | {"Type":"ADDRESS","IsArtifact":"False","IsEnriched":"False","IsVulnerable":"False","IsInternalAsset":"False","OriginalIdentifier":"999.999.999.999"} | **-** ***displayName***: Default<br/> ***highlighted***: False<br/> ***hidden***: False<br/> **items**:<br/>  **-** ***name***: Network_Priority<br/>   ***originalName***: Network_Priority<br/>   ***value***: 0<br/>  **-** ***name***: IsSuspicious<br/>   ***originalName***: IsSuspicious<br/>   ***value***: False<br/>  **-** ***name***: IsAttacker<br/>   ***originalName***: IsAttacker<br/>   ***value***: False<br/>  **-** ***name***: IsManuallyCreated<br/>   ***originalName***: IsManuallyCreated<br/>   ***value***: False<br/>  **-** ***name***: Environment<br/>   ***originalName***: Environment<br/>   ***value***: Default Environment<br/>  **-** ***name***: Alert_Id<br/>   ***originalName***: Alert_Id<br/>   ***value***: Testing Alert_62923d4f-05f0-47bf-9290-d0c94406e775<br/>  **-** ***name***: Type<br/>   ***originalName***: Type<br/>   ***value***: ADDRESS<br/>  **-** ***name***: IsArtifact<br/>   ***originalName***: IsArtifact<br/>   ***value***: False<br/>  **-** ***name***: IsEnriched<br/>   ***originalName***: IsEnriched<br/>   ***value***: False<br/>  **-** ***name***: IsVulnerable<br/>   ***originalName***: IsVulnerable<br/>   ***value***: False<br/>  **-** ***name***: IsInternalAsset<br/>   ***originalName***: IsInternalAsset<br/>   ***value***: False<br/>  **-** ***name***: OriginalIdentifier<br/>   ***originalName***: OriginalIdentifier<br/>   ***value***: 999.999.999.999<br/>**-** ***displayName***: Entity<br/> ***highlighted***: False<br/> ***hidden***: False<br/> **items**:<br/>  **-** ***name***: Is Pivot<br/>   ***originalName***: IsPivot<br/>   ***value***: False |

### gcb-case-alert-entity-create

***
Manually create a new involved entity within a case alert.

#### Base Command

`gcb-case-alert-entity-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| identifier | Specify the identifier name of the entity (e.g. IP address, hostname value, process name). | Required |
| entity_type | Specify the type of the new entity.<br/><br/>Note: Immutable after creation. Possible values are: ADDRESS, HOSTNAME, PROCESS, USB. | Required |
| suspicious | Specify whether the entity is suspicious. Possible values are: true, false. Default is false. | Optional |
| internal | Specify whether the entity is internal to the organization. Possible values are: true, false. Default is false. | Optional |
| attacker | Specify whether the entity represents an attacker. Possible values are: true, false. | Optional |
| pivot | Specify whether the entity is a pivot entity common to multiple cases. Possible values are: true, false. | Optional |
| operating_system | Specify the operating system of the entity. | Optional |
| network_title | Specify the network name related to the entity. | Optional |
| threat_source | Specify the threat source name associated with the entity. | Optional |
| network_priority | Specify the network priority of the entity (non-negative integer). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.AlertEntity.id | String | The immutable identifier of the Involved Entity. |
| GoogleSecOps.AlertEntity.identifier | String | The identifier name of the Involved Entity. |
| GoogleSecOps.AlertEntity.type | String | The type of the Involved Entity. |
| GoogleSecOps.AlertEntity.alertId | String | The Alert ID the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.caseId | Number | The Case ID the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.alertIdentifier | String | The alert identifier the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.environment | String | The environment of the Involved Entity. |
| GoogleSecOps.AlertEntity.threatSource | String | The threat source associated with the Involved Entity. |
| GoogleSecOps.AlertEntity.operatingSystem | String | The operating system of the Involved Entity. |
| GoogleSecOps.AlertEntity.networkTitle | String | The network name related to the Involved Entity. |
| GoogleSecOps.AlertEntity.networkPriority | Number | The network priority of the Involved Entity. |
| GoogleSecOps.AlertEntity.entityUri | String | The full URL of the Involved Entity in the source system. |
| GoogleSecOps.AlertEntity.sourceSystemUri | String | The source system URI link of the Involved Entity. |
| GoogleSecOps.AlertEntity.additionalProperties | String | The additional properties of the Involved Entity as a JSON string. |
| GoogleSecOps.AlertEntity.suspicious | Boolean | Whether the Involved Entity is considered suspicious. |
| GoogleSecOps.AlertEntity.internal | Boolean | Whether the Involved Entity is internal. |
| GoogleSecOps.AlertEntity.attacker | Boolean | Whether the Involved Entity represents an attacker. |
| GoogleSecOps.AlertEntity.pivot | Boolean | Whether the Involved Entity is a pivot entity common to multiple cases. |
| GoogleSecOps.AlertEntity.manuallyCreated | Boolean | Whether the Involved Entity was added manually. |
| GoogleSecOps.AlertEntity.enriched | Boolean | Whether the Involved Entity has been enriched by an external action. |
| GoogleSecOps.AlertEntity.artifact | Boolean | Whether the Involved Entity is an artifact. |
| GoogleSecOps.AlertEntity.vulnerable | Boolean | Whether the Involved Entity is vulnerable. |
| GoogleSecOps.AlertEntity.fields.displayName | String | The display name of the context group of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.highlighted | Boolean | Whether the context group of the Involved Entity is highlighted. |
| GoogleSecOps.AlertEntity.fields.hidden | Boolean | Whether the context group of the Involved Entity is hidden. |
| GoogleSecOps.AlertEntity.fields.items.name | String | The property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.originalName | String | The original property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.value | String | The value of the context group item of the Involved Entity. |

#### Command example

```!gcb-case-alert-entity-create case_id=123456 alert_id=1001 identifier=192.0.2.1 entity_type=ADDRESS suspicious=true```

#### Context Example

```json
{
    "GoogleSecOps": {
        "AlertEntity": {
            "id": "111111",
            "type": "ADDRESS",
            "suspicious": true,
            "internal": false,
            "networkPriority": 0,
            "attacker": false,
            "pivot": false,
            "environment": "Default Environment",
            "manuallyCreated": true,
            "additionalProperties": "{\"Type\":\"ADDRESS\",\"IsArtifact\":\"False\",\"IsEnriched\":\"False\",\"IsVulnerable\":\"False\",\"IsInternalAsset\":\"False\",\"OriginalIdentifier\":\"192.0.2.1\"}",
            "enriched": false,
            "artifact": false,
            "vulnerable": false,
            "fields": [
                {
                    "displayName": "Default",
                    "highlighted": false,
                    "hidden": false,
                    "items": [
                        {
                            "name": "Network_Priority",
                            "originalName": "Network_Priority",
                            "value": "0"
                        },
                        {
                            "name": "IsSuspicious",
                            "originalName": "IsSuspicious",
                            "value": "True"
                        },
                        {
                            "name": "IsAttacker",
                            "originalName": "IsAttacker",
                            "value": "False"
                        },
                        {
                            "name": "IsManuallyCreated",
                            "originalName": "IsManuallyCreated",
                            "value": "True"
                        },
                        {
                            "name": "Environment",
                            "originalName": "Environment",
                            "value": "Default Environment"
                        },
                        {
                            "name": "Alert_Id",
                            "originalName": "Alert_Id",
                            "value": "Testing Alert_00000000-0000-0000-0000-000000000001"
                        }
                    ]
                },
                {
                    "displayName": "Entity",
                    "highlighted": false,
                    "hidden": false,
                    "items": [
                        {
                            "name": "Is Pivot",
                            "originalName": "IsPivot",
                            "value": "False"
                        }
                    ]
                }
            ],
            "alertIdentifier": "Testing Alert_00000000-0000-0000-0000-000000000001",
            "caseId": 123456,
            "alertId": "1001",
            "identifier": "192.0.2.1"
        }
    }
}
```

#### Human Readable Output

>### Entity Information
>
>|ID|Identifier|Alert ID|Case ID|Alert Identifier|Type|Environment|Suspicious|Internal|Attacker|Pivot|Enriched|Artifact|Vulnerable|Manually Created|Network Priority|Additional Properties|Fields|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 111111 | 192.0.2.1 | 1001 | 123456 | Testing Alert_00000000-0000-0000-0000-000000000001 | ADDRESS | Default Environment | True | False | False | False | False | False | False | True | 0 | {"Type":"ADDRESS","IsArtifact":"False","IsEnriched":"False","IsVulnerable":"False","IsInternalAsset":"False","OriginalIdentifier":"192.0.2.1"} | **-** ***displayName***: Default<br/> ***highlighted***: False<br/> ***hidden***: False<br/> **items**:<br/>  **-** ***name***: Network_Priority<br/>   ***originalName***: Network_Priority<br/>   ***value***: 0<br/>  **-** ***name***: IsSuspicious<br/>   ***originalName***: IsSuspicious<br/>   ***value***: True<br/>  **-** ***name***: IsAttacker<br/>   ***originalName***: IsAttacker<br/>   ***value***: False<br/>  **-** ***name***: IsManuallyCreated<br/>   ***originalName***: IsManuallyCreated<br/>   ***value***: True<br/>  **-** ***name***: Environment<br/>   ***originalName***: Environment<br/>   ***value***: Default Environment<br/>  **-** ***name***: Alert_Id<br/>   ***originalName***: Alert_Id<br/>   ***value***: Testing Alert_00000000-0000-0000-0000-000000000001<br/>**-** ***displayName***: Entity<br/> ***highlighted***: False<br/> ***hidden***: False<br/> **items**:<br/>  **-** ***name***: Is Pivot<br/>   ***originalName***: IsPivot<br/>   ***value***: False |

### gcb-case-alert-entity-update

***
Update the attributes of an existing involved entity in a case alert.

#### Base Command

`gcb-case-alert-entity-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| entity_id | Specify the ID of the involved entity to update.<br/><br/>Note: Use gcb-case-alert-entity-list to retrieve entity ID. | Required |
| suspicious | Specify the updated suspicion flag for the entity. Possible values are: true, false. | Optional |
| internal | Specify the updated internal flag for the entity. Possible values are: true, false. | Optional |
| attacker | Specify the updated attacker designation for the entity. Possible values are: true, false. | Optional |
| pivot | Specify the updated pivot designation for the entity. Possible values are: true, false. | Optional |
| operating_system | Specify the updated operating system of the entity. | Optional |
| network_title | Specify the updated network name related to the entity. | Optional |
| threat_source | Specify the updated threat source associated with the entity. | Optional |
| network_priority | Specify the updated network priority associated with the entity (non-negative integer). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.AlertEntity.id | String | The immutable identifier of the Involved Entity. |
| GoogleSecOps.AlertEntity.identifier | String | The identifier name of the Involved Entity. |
| GoogleSecOps.AlertEntity.type | String | The type of the Involved Entity. |
| GoogleSecOps.AlertEntity.alertId | String | The Alert ID the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.caseId | Number | The Case ID the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.alertIdentifier | String | The alert identifier the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.environment | String | The environment of the Involved Entity. |
| GoogleSecOps.AlertEntity.threatSource | String | The threat source associated with the Involved Entity. |
| GoogleSecOps.AlertEntity.operatingSystem | String | The operating system of the Involved Entity. |
| GoogleSecOps.AlertEntity.networkTitle | String | The network name related to the Involved Entity. |
| GoogleSecOps.AlertEntity.networkPriority | Number | The network priority of the Involved Entity. |
| GoogleSecOps.AlertEntity.entityUri | String | The full URL of the Involved Entity in the source system. |
| GoogleSecOps.AlertEntity.sourceSystemUri | String | The source system URI link of the Involved Entity. |
| GoogleSecOps.AlertEntity.additionalProperties | String | The additional properties of the Involved Entity as a JSON string. |
| GoogleSecOps.AlertEntity.suspicious | Boolean | Whether the Involved Entity is considered suspicious. |
| GoogleSecOps.AlertEntity.internal | Boolean | Whether the Involved Entity is internal. |
| GoogleSecOps.AlertEntity.attacker | Boolean | Whether the Involved Entity represents an attacker. |
| GoogleSecOps.AlertEntity.pivot | Boolean | Whether the Involved Entity is a pivot entity common to multiple cases. |
| GoogleSecOps.AlertEntity.manuallyCreated | Boolean | Whether the Involved Entity was added manually. |
| GoogleSecOps.AlertEntity.enriched | Boolean | Whether the Involved Entity has been enriched by an external action. |
| GoogleSecOps.AlertEntity.artifact | Boolean | Whether the Involved Entity is an artifact. |
| GoogleSecOps.AlertEntity.vulnerable | Boolean | Whether the Involved Entity is vulnerable. |
| GoogleSecOps.AlertEntity.fields.displayName | String | The display name of the context group of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.highlighted | Boolean | Whether the context group of the Involved Entity is highlighted. |
| GoogleSecOps.AlertEntity.fields.hidden | Boolean | Whether the context group of the Involved Entity is hidden. |
| GoogleSecOps.AlertEntity.fields.items.name | String | The property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.originalName | String | The original property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.value | String | The value of the context group item of the Involved Entity. |

#### Command example

```!gcb-case-alert-entity-update case_id=306082 alert_id=1001 entity_id=376398 suspicious=true attacker=true network_priority=5```

#### Context Example

```json
{
    "GoogleSecOps": {
        "AlertEntity": {
            "id": "376398",
            "type": "ADDRESS",
            "suspicious": true,
            "internal": false,
            "networkPriority": 5,
            "attacker": true,
            "pivot": false,
            "environment": "Default Environment",
            "manuallyCreated": true,
            "additionalProperties": "{\"Type\":\"ADDRESS\",\"IsArtifact\":\"False\",\"IsEnriched\":\"False\",\"IsVulnerable\":\"False\",\"IsInternalAsset\":\"False\",\"OriginalIdentifier\":\"192.0.2.1\"}",
            "enriched": false,
            "artifact": false,
            "vulnerable": false,
            "fields": [
                {
                    "displayName": "Default",
                    "highlighted": false,
                    "hidden": false,
                    "items": [
                        {
                            "name": "Network_Priority",
                            "originalName": "Network_Priority",
                            "value": "5"
                        },
                        {
                            "name": "IsSuspicious",
                            "originalName": "IsSuspicious",
                            "value": "True"
                        },
                        {
                            "name": "IsAttacker",
                            "originalName": "IsAttacker",
                            "value": "True"
                        },
                        {
                            "name": "IsManuallyCreated",
                            "originalName": "IsManuallyCreated",
                            "value": "True"
                        },
                        {
                            "name": "Environment",
                            "originalName": "Environment",
                            "value": "Default Environment"
                        },
                        {
                            "name": "Alert_Id",
                            "originalName": "Alert_Id",
                            "value": "Testing Alert_00000000-0000-0000-0000-000000000001"
                        }
                    ]
                },
                {
                    "displayName": "Entity",
                    "highlighted": false,
                    "hidden": false,
                    "items": [
                        {
                            "name": "Is Pivot",
                            "originalName": "IsPivot",
                            "value": "False"
                        }
                    ]
                }
            ],
            "alertIdentifier": "Testing Alert_00000000-0000-0000-0000-000000000001",
            "caseId": 306082,
            "alertId": "1001",
            "identifier": "192.0.2.1"
        }
    }
}
```

#### Human Readable Output

>### Updated Entity Information
>
>|ID|Identifier|Alert ID|Case ID|Alert Identifier|Type|Environment|Suspicious|Internal|Attacker|Pivot|Enriched|Artifact|Vulnerable|Manually Created|Network Priority|Additional Properties|Fields|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 376398 | 192.0.2.1 | 1001 | 306082 | Testing Alert_00000000-0000-0000-0000-000000000001 | ADDRESS | Default Environment | True | False | True | False | False | False | False | True | 5 | {"Type":"ADDRESS","IsArtifact":"False","IsEnriched":"False","IsVulnerable":"False","IsInternalAsset":"False","OriginalIdentifier":"192.0.2.1"} | **-** ***displayName***: Default<br/> ***highlighted***: False<br/> ***hidden***: False<br/> **items**:<br/>  **-** ***name***: Network_Priority<br/>   ***originalName***: Network_Priority<br/>   ***value***: 5<br/>  **-** ***name***: IsSuspicious<br/>   ***originalName***: IsSuspicious<br/>   ***value***: True<br/>  **-** ***name***: IsAttacker<br/>   ***originalName***: IsAttacker<br/>   ***value***: True<br/>  **-** ***name***: IsManuallyCreated<br/>   ***originalName***: IsManuallyCreated<br/>   ***value***: True<br/>  **-** ***name***: Environment<br/>   ***originalName***: Environment<br/>   ***value***: Default Environment<br/>  **-** ***name***: Alert_Id<br/>   ***originalName***: Alert_Id<br/>   ***value***: Testing Alert_00000000-0000-0000-0000-000000000001<br/>**-** ***displayName***: Entity<br/> ***highlighted***: False<br/> ***hidden***: False<br/> **items**:<br/>  **-** ***name***: Is Pivot<br/>   ***originalName***: IsPivot<br/>   ***value***: False |

### gcb-case-alert-entity-property-add

***
Add a new custom property to an involved entity in a case alert.

#### Base Command

`gcb-case-alert-entity-property-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| entity_id | Specify the ID of the involved entity to add a property.<br/><br/>Note: Use gcb-case-alert-entity-list to retrieve entity ID. | Required |
| key | Specify the property key to add.<br/><br/>Note: The key must not already exist on the entity. | Required |
| value | Specify the value for the new property. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.AlertEntity.id | String | The immutable identifier of the Involved Entity. |
| GoogleSecOps.AlertEntity.identifier | String | The identifier name of the Involved Entity. |
| GoogleSecOps.AlertEntity.type | String | The type of the Involved Entity. |
| GoogleSecOps.AlertEntity.alertId | String | The Alert ID the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.caseId | Number | The Case ID the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.alertIdentifier | String | The alert identifier the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.environment | String | The environment of the Involved Entity. |
| GoogleSecOps.AlertEntity.threatSource | String | The threat source associated with the Involved Entity. |
| GoogleSecOps.AlertEntity.operatingSystem | String | The operating system of the Involved Entity. |
| GoogleSecOps.AlertEntity.networkTitle | String | The network name related to the Involved Entity. |
| GoogleSecOps.AlertEntity.networkPriority | Number | The network priority of the Involved Entity. |
| GoogleSecOps.AlertEntity.entityUri | String | The full URL of the Involved Entity in the source system. |
| GoogleSecOps.AlertEntity.sourceSystemUri | String | The source system URI link of the Involved Entity. |
| GoogleSecOps.AlertEntity.additionalProperties | String | The additional properties of the Involved Entity as a JSON string. |
| GoogleSecOps.AlertEntity.suspicious | Boolean | Whether the Involved Entity is considered suspicious. |
| GoogleSecOps.AlertEntity.internal | Boolean | Whether the Involved Entity is internal. |
| GoogleSecOps.AlertEntity.attacker | Boolean | Whether the Involved Entity represents an attacker. |
| GoogleSecOps.AlertEntity.pivot | Boolean | Whether the Involved Entity is a pivot entity common to multiple cases. |
| GoogleSecOps.AlertEntity.manuallyCreated | Boolean | Whether the Involved Entity was added manually. |
| GoogleSecOps.AlertEntity.enriched | Boolean | Whether the Involved Entity has been enriched by an external action. |
| GoogleSecOps.AlertEntity.artifact | Boolean | Whether the Involved Entity is an artifact. |
| GoogleSecOps.AlertEntity.vulnerable | Boolean | Whether the Involved Entity is vulnerable. |
| GoogleSecOps.AlertEntity.fields.displayName | String | The display name of the context group of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.highlighted | Boolean | Whether the context group of the Involved Entity is highlighted. |
| GoogleSecOps.AlertEntity.fields.hidden | Boolean | Whether the context group of the Involved Entity is hidden. |
| GoogleSecOps.AlertEntity.fields.items.name | String | The property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.originalName | String | The original property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.value | String | The value of the context group item of the Involved Entity. |

#### Command example

```!gcb-case-alert-entity-property-add case_id=306082 alert_id=1001 entity_id=376398 key=total_score value=42/72```

#### Context Example

```json
{
    "GoogleSecOps": {
        "AlertEntity": {
            "id": "376398",
            "type": "ADDRESS",
            "suspicious": true,
            "internal": false,
            "networkPriority": 5,
            "attacker": true,
            "pivot": false,
            "environment": "Default Environment",
            "manuallyCreated": true,
            "additionalProperties": "{\"Type\":\"ADDRESS\",\"IsArtifact\":\"False\",\"IsEnriched\":\"False\",\"IsVulnerable\":\"False\",\"IsInternalAsset\":\"False\",\"OriginalIdentifier\":\"192.0.2.1\"}",
            "enriched": true,
            "artifact": false,
            "vulnerable": false,
            "fields": [
                {
                    "displayName": "Default",
                    "highlighted": false,
                    "hidden": false,
                    "items": [
                        {"name": "Network_Priority", "originalName": "Network_Priority", "value": "5"},
                        {"name": "IsSuspicious", "originalName": "IsSuspicious", "value": "True"},
                        {"name": "IsAttacker", "originalName": "IsAttacker", "value": "True"},
                        {"name": "IsManuallyCreated", "originalName": "IsManuallyCreated", "value": "True"},
                        {"name": "Environment", "originalName": "Environment", "value": "Default Environment"},
                        {"name": "Alert_Id", "originalName": "Alert_Id", "value": "Testing Alert_00000000-0000-0000-0000-000000000001"}
                    ]
                },
                {
                    "displayName": "Entity",
                    "highlighted": false,
                    "hidden": false,
                    "items": [{"name": "Is Pivot", "originalName": "IsPivot", "value": "False"}]
                },
                {
                    "displayName": "Enrichment",
                    "highlighted": false,
                    "hidden": false,
                    "items": [{"name": "Total Score", "originalName": "Total Score", "value": "42/72"}]
                }
            ],
            "alertIdentifier": "Testing Alert_00000000-0000-0000-0000-000000000001",
            "caseId": 306082,
            "alertId": "1001",
            "identifier": "192.0.2.1"
        }
    }
}
```

#### Human Readable Output

>Added Entity Property with key `total_score` and value `42/72`.

### gcb-case-alert-entity-property-update

***
Update an existing custom property value on an involved entity in a case alert.

#### Base Command

`gcb-case-alert-entity-property-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_id | Specify the ID of the case alert.<br/><br/>Note: Use gcb-case-alert-list to retrieve alert ID. | Required |
| entity_id | Specify the ID of the involved entity to update the property.<br/><br/>Note: Use gcb-case-alert-entity-list to retrieve entity ID. | Required |
| key | Specify the existing property key whose value should be updated. | Required |
| value | Specify the new value for the property. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.AlertEntity.id | String | The immutable identifier of the Involved Entity. |
| GoogleSecOps.AlertEntity.identifier | String | The identifier name of the Involved Entity. |
| GoogleSecOps.AlertEntity.type | String | The type of the Involved Entity. |
| GoogleSecOps.AlertEntity.alertId | String | The Alert ID the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.caseId | Number | The Case ID the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.alertIdentifier | String | The alert identifier the Involved Entity belongs to. |
| GoogleSecOps.AlertEntity.environment | String | The environment of the Involved Entity. |
| GoogleSecOps.AlertEntity.threatSource | String | The threat source associated with the Involved Entity. |
| GoogleSecOps.AlertEntity.operatingSystem | String | The operating system of the Involved Entity. |
| GoogleSecOps.AlertEntity.networkTitle | String | The network name related to the Involved Entity. |
| GoogleSecOps.AlertEntity.networkPriority | Number | The network priority of the Involved Entity. |
| GoogleSecOps.AlertEntity.entityUri | String | The full URL of the Involved Entity in the source system. |
| GoogleSecOps.AlertEntity.sourceSystemUri | String | The source system URI link of the Involved Entity. |
| GoogleSecOps.AlertEntity.additionalProperties | String | The additional properties of the Involved Entity as a JSON string. |
| GoogleSecOps.AlertEntity.suspicious | Boolean | Whether the Involved Entity is considered suspicious. |
| GoogleSecOps.AlertEntity.internal | Boolean | Whether the Involved Entity is internal. |
| GoogleSecOps.AlertEntity.attacker | Boolean | Whether the Involved Entity represents an attacker. |
| GoogleSecOps.AlertEntity.pivot | Boolean | Whether the Involved Entity is a pivot entity common to multiple cases. |
| GoogleSecOps.AlertEntity.manuallyCreated | Boolean | Whether the Involved Entity was added manually. |
| GoogleSecOps.AlertEntity.enriched | Boolean | Whether the Involved Entity has been enriched by an external action. |
| GoogleSecOps.AlertEntity.artifact | Boolean | Whether the Involved Entity is an artifact. |
| GoogleSecOps.AlertEntity.vulnerable | Boolean | Whether the Involved Entity is vulnerable. |
| GoogleSecOps.AlertEntity.fields.displayName | String | The display name of the context group of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.highlighted | Boolean | Whether the context group of the Involved Entity is highlighted. |
| GoogleSecOps.AlertEntity.fields.hidden | Boolean | Whether the context group of the Involved Entity is hidden. |
| GoogleSecOps.AlertEntity.fields.items.name | String | The property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.originalName | String | The original property name of the context group item of the Involved Entity. |
| GoogleSecOps.AlertEntity.fields.items.value | String | The value of the context group item of the Involved Entity. |

#### Command example

```!gcb-case-alert-entity-property-update case_id=306082 alert_id=1001 entity_id=376398 key=total_score value=68/72```

#### Context Example

```json
{
    "GoogleSecOps": {
        "AlertEntity": {
            "id": "376398",
            "type": "ADDRESS",
            "suspicious": true,
            "internal": false,
            "networkPriority": 5,
            "attacker": true,
            "pivot": false,
            "environment": "Default Environment",
            "manuallyCreated": true,
            "additionalProperties": "{\"Type\":\"ADDRESS\",\"IsArtifact\":\"False\",\"IsEnriched\":\"False\",\"IsVulnerable\":\"False\",\"IsInternalAsset\":\"False\",\"OriginalIdentifier\":\"192.0.2.1\"}",
            "enriched": true,
            "artifact": false,
            "vulnerable": false,
            "fields": [
                {
                    "displayName": "Default",
                    "highlighted": false,
                    "hidden": false,
                    "items": [
                        {"name": "Network_Priority", "originalName": "Network_Priority", "value": "5"},
                        {"name": "IsSuspicious", "originalName": "IsSuspicious", "value": "True"},
                        {"name": "IsAttacker", "originalName": "IsAttacker", "value": "True"},
                        {"name": "IsManuallyCreated", "originalName": "IsManuallyCreated", "value": "True"},
                        {"name": "Environment", "originalName": "Environment", "value": "Default Environment"},
                        {"name": "Alert_Id", "originalName": "Alert_Id", "value": "Testing Alert_00000000-0000-0000-0000-000000000001"}
                    ]
                },
                {
                    "displayName": "Entity",
                    "highlighted": false,
                    "hidden": false,
                    "items": [{"name": "Is Pivot", "originalName": "IsPivot", "value": "False"}]
                },
                {
                    "displayName": "Enrichment",
                    "highlighted": false,
                    "hidden": false,
                    "items": [{"name": "Total Score", "originalName": "Total Score", "value": "68/72"}]
                }
            ],
            "alertIdentifier": "Testing Alert_00000000-0000-0000-0000-000000000001",
            "caseId": 306082,
            "alertId": "1001",
            "identifier": "192.0.2.1"
        }
    }
}
```

#### Human Readable Output

>Updated Entity Property with key `total_score` and value `68/72`.

### gcb-playbook-list

***
Retrieve the list of all playbooks that are currently enabled and ready for execution.

#### Base Command

`gcb-playbook-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| environment | Filter the playbooks by environment. | Optional |
| execution_scope | Filter the playbooks attachable by the specified execution scope. Possible values are: ALERT, CASE, EXECUTION_SCOPE_UNSPECIFIED. Default is ALERT. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.Playbook.playbookName | String | The name of the enabled playbook. |
| GoogleSecOps.Playbook.description | String | The description of the playbook. |
| GoogleSecOps.Playbook.playbookType | String | The type of the playbook (REGULAR or NESTED). |
| GoogleSecOps.Playbook.originalWorkflowDefinitionIdentifier | String | The original workflow definition identifier of the playbook. |
| GoogleSecOps.Playbook.workflowDefinitionIdentifier | String | The workflow definition identifier of the playbook. |
| GoogleSecOps.Playbook.isDebugMode | Boolean | Whether the playbook is running in debug mode. |

#### Command example

```!gcb-playbook-list execution_scope=ALERT```

#### Context Example

```json
{
    "GoogleSecOps": {
        "Playbook": [
            {
                "playbookName": "IMPORT 5 - Network Containment Block - Google",
                "description": "Automated IP containment playbook that queries Google using CVE identifiers, extracts malicious IPs, creates entities in alerts, and blocks them via Zscaler. Supports real-time threat intelligence-based network containment.",
                "playbookType": "NESTED",
                "isDebugMode": true,
                "originalWorkflowDefinitionIdentifier": "00000000-0000-0000-0000-000000000001",
                "workflowDefinitionIdentifier": "00000000-0000-0000-0000-000000000001"
            },
            {
                "playbookName": "Google Cloud Compute Platform Starting Playbook",
                "description": "Google Cloud Compute Platform Starting Playbook provides reference implementation of how Google Cloud Compute Platform alerts can be processed in Google SecOps.",
                "playbookType": "REGULAR",
                "isDebugMode": false,
                "originalWorkflowDefinitionIdentifier": "00000000-0000-0000-0000-000000000002",
                "workflowDefinitionIdentifier": "00000000-0000-0000-0000-000000000002"
            },
            {
                "playbookName": "Set Initial Severity",
                "description": "An embedded workflow that can receive inputs and return an output.",
                "playbookType": "NESTED",
                "isDebugMode": true,
                "originalWorkflowDefinitionIdentifier": "00000000-0000-0000-0000-000000000003",
                "workflowDefinitionIdentifier": "00000000-0000-0000-0000-000000000003"
            },
            {
                "playbookName": "Google - Network Containment Block",
                "description": "Automated IP containment playbook that queries Google using CVE identifiers, extracts malicious IPs, creates entities in alerts, and blocks them via Zscaler. Supports real-time threat intelligence-based network containment.",
                "playbookType": "NESTED",
                "isDebugMode": false,
                "originalWorkflowDefinitionIdentifier": "00000000-0000-0000-0000-000000000004",
                "workflowDefinitionIdentifier": "00000000-0000-0000-0000-000000000005"
            }
        ]
    }
}
```

#### Human Readable Output

>### Enabled Playbooks
>
>|Playbook Name|Description|Playbook Type|Original Workflow Definition Identifier|Workflow Definition Identifier|Is Debug Mode|
>|---|---|---|---|---|---|
>| IMPORT 5 - Network Containment Block - Google | Automated IP containment playbook that queries Google using CVE identifiers, extracts malicious IPs, creates entities in alerts, and blocks them via Zscaler. Supports real-time threat intelligence-based network containment. | NESTED | 00000000-0000-0000-0000-000000000001 | 00000000-0000-0000-0000-000000000001 | True |
>| Google Cloud Compute Platform Starting Playbook | Google Cloud Compute Platform Starting Playbook provides reference implementation of how Google Cloud Compute Platform alerts can be processed in Google SecOps. | REGULAR | 00000000-0000-0000-0000-000000000002 | 00000000-0000-0000-0000-000000000002 | False |
>| Set Initial Severity | An embedded workflow that can receive inputs and return an output. | NESTED | 00000000-0000-0000-0000-000000000003 | 00000000-0000-0000-0000-000000000003 | True |
>| Google - Network Containment Block | Automated IP containment playbook that queries Google using CVE identifiers, extracts malicious IPs, creates entities in alerts, and blocks them via Zscaler. Supports real-time threat intelligence-based network containment. | NESTED | 00000000-0000-0000-0000-000000000004 | 00000000-0000-0000-0000-000000000005 | False |

### gcb-playbook-attach

***
Manually attach (trigger) a specific playbook to a case alert.

#### Base Command

`gcb-playbook-attach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Specify the ID of the case to attach the playbook.<br/><br/>Note: Use gcb-case-list to retrieve case ID. | Required |
| alert_group_identifier | Specify the alert group identifier of the case alert.<br/><br/>Note: Use gcb-case-alert-get to retrieve the alert group identifier. | Required |
| alert_identifier | Specify the alert identifier of the case alert.<br/><br/>Note: Use gcb-case-alert-get to retrieve the alert identifier. | Required |
| playbook_name | Specify the name of the playbook (workflow) to attach.<br/><br/>Note: Use gcb-playbook-list to retrieve available playbook names. | Required |
| original_workflow_definition_identifier | Specify the original workflow definition identifier of the playbook.<br/><br/>Note: Use gcb-playbook-list to retrieve the original workflow definition identifier. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleSecOps.PlaybookAttach.caseId | String | The Case ID the playbook was attached to. |
| GoogleSecOps.PlaybookAttach.alertGroupIdentifier | String | The alert group identifier the playbook was attached to. |
| GoogleSecOps.PlaybookAttach.alertIdentifier | String | The alert identifier the playbook was attached to. |
| GoogleSecOps.PlaybookAttach.playbookName | String | The name of the playbook that was attached. |
| GoogleSecOps.PlaybookAttach.originalWorkflowDefinitionIdentifier | String | The original workflow definition identifier of the attached playbook. |
| GoogleSecOps.PlaybookAttach.success | Boolean | Whether the playbook was successfully attached to the alert. |

#### Command example

```!gcb-playbook-attach case_id=1001 alert_group_identifier="Access Disabled Accounts_00000000-0000-0000-0000-000000000001" alert_identifier="ACCESS DISABLED ACCOUNTS_00000000-0000-0000-0000-000000000002" playbook_name="Phishing Investigation" original_workflow_definition_identifier="00000000-0000-0000-0000-000000000001"```

#### Context Example

```json
{
    "GoogleSecOps": {
        "PlaybookAttach": {
            "caseId": "1001",
            "alertGroupIdentifier": "Access Disabled Accounts_00000000-0000-0000-0000-000000000001",
            "alertIdentifier": "ACCESS DISABLED ACCOUNTS_00000000-0000-0000-0000-000000000002",
            "playbookName": "Phishing Investigation",
            "originalWorkflowDefinitionIdentifier": "00000000-0000-0000-0000-000000000001",
            "success": true
        }
    }
}
```

#### Human Readable Output

>Playbook 'Phishing Investigation' successfully attached to alert ACCESS DISABLED ACCOUNTS_00000000-0000-0000-0000-000000000002 in case 1001.
