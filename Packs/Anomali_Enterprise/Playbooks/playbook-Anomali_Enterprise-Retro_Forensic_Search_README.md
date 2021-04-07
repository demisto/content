Initiates a Forensic Search on IOCs in Anomali Match.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Anomali Match

### Scripts
This playbook does not use any scripts.

### Commands
* anomali-enterprise-retro-forensic-search-results
* anomali-enterprise-retro-forensic-search

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| from | First appearance time range e.g., 1 hour, 30 minutes\). |  | Required |
| to | Last appearance time range e.g., 1 hour, 30 minutes\). Default is now. |  | Optional |
| indicators | Indicators to search. |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AnomaliEnterprise.ForensicSearch.job_id | Job ID of the search. | string |
| AnomaliEnterprise.ForensicSearch.status | Status of the search. | string |
| AnomaliEnterprise.ForensicSearch.scannedEvents | Number of scanned events. | number |
| AnomaliEnterprise.ForensicSearch.processedFiles | Number of processed files. | number |
| AnomaliEnterprise.ForensicSearch.result_file_name | Matched file name. | string |
| AnomaliEnterprise.ForensicSearch.totalMatches | Number of total matches. | number |
| AnomaliEnterprise.ForensicSearch.complete | Whether the search was complete. | boolean |
| AnomaliEnterprise.ForensicSearch.category | Search category. | string |
| AnomaliEnterprise.ForensicSearch.streamResults | Stream results for the search. | unknown |
