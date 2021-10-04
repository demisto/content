Runs a QRadar query and return its results to the context.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* qradar-get-search-results
* qradar-get-search
* qradar-searches

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |  
| timeout | The amount of time to wait before a timeout occurs (in minutes). | 600 | Optional |
| interval | The polling frequency. How often the polling command should run (in minutes). | 1 |Optional |
| query_expression | The query expressions in AQL. | - |Required |
| range | The range of results to return. For example, 0-20. | - | Optional |
| headers | The table headers. | - | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| QRadar.Search.Result | The results of the search. | unknown |

## Playbook Image
---
![QRadarFullSearch](../doc_files/QRadarFullSearch.png)
