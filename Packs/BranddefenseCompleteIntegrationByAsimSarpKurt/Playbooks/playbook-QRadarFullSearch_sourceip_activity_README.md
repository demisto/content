This playbook runs a QRadar query and return its results to the context.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* QRadarV3Copy
* QRadar v3

### Scripts

* Sleep

### Commands

* qradar-search-results-get
* qradar-get-search-results
* qradar-searches
* qradar-search-retrieve-events
* qradar-search-create
* qradar-get-search

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| timeout | How much time to wait before a timeout occurs \(minutes\) | 600 | Optional |
| interval | Polling frequency - how often the polling command should run \(minutes\) | 1 | Optional |
| query_expression | The query expressions in AQL | select QIDNAME(qid) as 'Event Name',logsourcename(logSourceId) as 'Log Source',"eventCount" as 'Event Count',"startTime" as 'Time',categoryname(category) as 'Low Level Category',"sourceIP" as 'Source IP',"sourcePort" as 'Source Port',"destinationIP" as 'Destination IP',"destinationPort" as 'Destination Port',"userName" as 'Username',"magnitude" as 'Magnitude' from events where ( "username"='${incident.username}'  ) order by "startTime" desc LIMIT 998 last 30 minutes | Required |
| range | Range of results to return \(e.g. 0-20\) |  | Optional |
| headers | Table headers |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| QRadar.Search.Result | The result of the search | unknown |

## Playbook Image

---

![QRadarFullSearch_sourceip_activity](../doc_files/QRadarFullSearch_sourceip_activity.png)
