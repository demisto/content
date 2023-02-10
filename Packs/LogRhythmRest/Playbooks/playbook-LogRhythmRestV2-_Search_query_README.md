This playbook used generic polling to get query results using the command: lr-execute-search-query.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* LogRhythmRestV2
* LogRhythmRest

### Scripts
This playbook does not use any scripts.

### Commands
* lr-get-query-result
* lr-execute-search-query

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| number_of_days | Number of days to search. | 7 | Required |
| search_name | Name of the search. |  | Optional |
| source_type | Log source type. |  | Optional |
| host_name | Impacted host name. |  | Optional |
| username | Username. |  | Optional |
| subject | Email subject. |  | Optional |
| sender | Email sender. |  | Optional |
| recipient | Email recipient. |  | Optional |
| hash | Hash. |  | Optional |
| URL | URL. |  | Optional |
| process_name | Process name. |  | Optional |
| object | Log object. |  | Optional |
| ip_address | IP address. |  | Optional |
| max_massage | Maximum number of log messages to query. | 10 | Optional |
| query_timeout | The query timeout in seconds. | 60 | Optional |
| entity_id | Entity ID. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| LogRhythm.Search.TaskStatus | Task Status. | string |
| LogRhythm.Search.TaskId | Task Id. | string |
| LogRhythm.Search.SearchName | The name of the search query in Cortex XSOAR. | string |
| LogRhythm.Search.Results.originEntityId | Entity ID. | number |
| LogRhythm.Search.Results.impactedIp | Impacted IP address. | string |
| LogRhythm.Search.Results.classificationTypeName | Classification name. | string |
| LogRhythm.Search.Results.logSourceName | Log source name. | string |
| LogRhythm.Search.Results.entityName | Entity name. | string |
| LogRhythm.Search.Results.normalDate | Date. | date |
| LogRhythm.Search.Results.vendorMessageId | Vendor log message. | string |
| LogRhythm.Search.Results.priority | Log priority. | number |
| LogRhythm.Search.Results.sequenceNumber | Sequence number. | string |
| LogRhythm.Search.Results.originHostId | Origin host ID. | number |
| LogRhythm.Search.Results.mpeRuleId | LogRhythm rule ID. | number |
| LogRhythm.Search.Results.originIp | Origin IP address. | string |
| LogRhythm.Search.Results.mpeRuleName | LogRhythm rule name. | string |
| LogRhythm.Search.Results.logSourceHostId | Log source host ID. | number |
| LogRhythm.Search.Results.originHost | Origin host. | string |
| LogRhythm.Search.Results.logDate | Log date. | date |
| LogRhythm.Search.Results.classificationName | Log classification name. | string |

## Playbook Image
---
![LogRhythmRestV2 - Search query](../doc_files/LogRhythmRestV2-_Search_query.png)