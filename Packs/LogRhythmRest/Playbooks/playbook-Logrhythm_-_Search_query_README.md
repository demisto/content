This playbook used generic polling to gets query result using the command: lr-execute-search-query

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* LogRhythmRest

### Scripts
This playbook does not use any scripts.

### Commands
* lr-execute-search-query
* lr-get-query-result

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| number_of_days | Number of days to search. | 7 | Required |
| source_type | Log source type. |  | Optional |
| host_name | Impacted host name. |  | Optional |
| username | Username. |  | Optional |
| subject | Email Subject. |  | Optional |
| sender | Email Sender. |  | Optional |
| recipient | Email Recipient. |  | Optional |
| hash | Hash. |  | Optional |
| URL | URL. |  | Optional |
| process_name | Process name. |  | Optional |
| object | Log object. |  | Optional |
| ip_address | IP Address. |  | Optional |
| max_massage | Max log message to query. | 10 | Optional |
| query_timeout | Execute search query to Log Rhythm log database. | 60 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Logrhythm.Search.Results.TaskStatus | Task Status | string |
| Logrhythm.Search.Results.TaskID | Task ID | string |
| Logrhythm.Search.Results.Items.originEntityId | Entity ID | number |
| Logrhythm.Search.Results.Items.impactedIp | Impacted IP | string |
| Logrhythm.Search.Results.Items.classificationTypeName | Classification Name | string |
| Logrhythm.Search.Results.Items.logSourceName | Log Source Name | string |
| Logrhythm.Search.Results.Items.entityName | Entity Name | string |
| Logrhythm.Search.Results.Items.normalDate | Date | date |
| Logrhythm.Search.Results.Items.vendorMessageId | Vendor Log message | string |
| Logrhythm.Search.Results.Items.priority | Log priority | number |
| Logrhythm.Search.Results.Items.sequenceNumber | Seq number | string |
| Logrhythm.Search.Results.Items.originHostId | Origin Host ID | number |
| Logrhythm.Search.Results.Items.mpeRuleId | Log Rhythm rule ID | number |
| Logrhythm.Search.Results.Items.originIp | Origin IP | string |
| Logrhythm.Search.Results.Items.mpeRuleName | Log Rhythm rule name | string |
| Logrhythm.Search.Results.Items.logSourceHostId | Log Source host ID | number |
| Logrhythm.Search.Results.Items.originHost | Origin Host | string |
| Logrhythm.Search.Results.Items.logDate | Log Date | date |
| Logrhythm.Search.Results.Items.classificationName | Log classification name | string |

## Playbook Image
---
![Logrhythm - Search query](../doc_files/Logrhythm_-_Search_query.png)