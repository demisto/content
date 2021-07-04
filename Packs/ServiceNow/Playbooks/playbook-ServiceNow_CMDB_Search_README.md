Subplaybook for finding CI records in ServiceNow CMDB.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* This does not use any sub-playbooks

### Integrations
* ServiceNow CMDB

### Scripts
* This playbook does not use any scripts.

### Commands
* servicenow-cmdb-records-list
* servicenow-cmdb-record-get-by-id

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SearchCIClass | The CMDB CI class to perform the search on. | cmdb_ci_network_adapter | Optional |
| SearchQueryField | The CI field used to perform the query. | ip_address | Optional |
| SearchQueryValue | The value used to perform the query. |  | Required |

## Playbook Outputs
---

| **Name** | **Description** |
| --- | --- |
| ServiceNowCMDB.Record | Discovered CI records. |


## Playbook Image
---
![ServiceNow CMDB Search](https://raw.githubusercontent.com/demisto/content/master/Packs/ServiceNow/doc_files/ServiceNow_CMDB_Search.png)
