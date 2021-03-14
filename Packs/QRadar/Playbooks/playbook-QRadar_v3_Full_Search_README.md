This playbook runs a QRadar query and return its results to the context.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* outputs
* QRadar v3

### Scripts
* PrintErrorEntry

### Commands
* qradar-search-results-get
* qradar-search-create
* qradar-search-status-get

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| query_expression | The AQL query to execute. Mutually exclusive with saved_search_id. |  | Optional |
| saved_search_id | Saved search ID to execute. Mutually exclusive with query_expression. Saved search ID is 'id' field returned by command 'qradar-saved-searches-list'. |  | Optional |
| range | Range of events to return. \(e.g.: 0-20, 3-5, 3-3\). |  | Optional |
| output_path | Replaces the default context output path for the query result \(QRadar.Search.Result\). e.g. for output_path=QRadar.Correlations the result will be under the key 'QRadar.Correlations' in the context data. |  | Optional |
| interval | Frequency that the polling command will run \(in minutes\). | 1 | Optional |
| timeout | Number of times that the polling command will run until declaring a timeout and resuming the playbook. | 10 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![QRadar v3 Full Search](https://raw.githubusercontent.com/demisto/content/63ef39300995a735e2d78e73b189a1106c8dbfe2/Packs/QRadar/doc_files/QRadar v3_Full_Search.png)