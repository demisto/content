Dumps memory if the given process is running on legacy AD agent. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
* GenericPolling

## Integrations
* Accessdata

## Scripts
* AccessdataCheckProcessExistsInSnapshot
* Set 

## Commands
* accessdata-get-jobstatus-memorydump
* accessdata-legacyagent-get-memorydump
* accessdata-get-jobstatus-processlist
* accessdata-legacyagent-get-processlist
* accessdata-read-casefile

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| target_ip |  | Required |
| process_name |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Accessdata.IsProcessDetected | Indicates if the process with the specified name was detected on the agent machine during playbook execution. | boolean |
| Accessdata.MemoryDumpPath | The path for the created memory dump file (if not created, it will be an empty string). | string |

## Playbook Image
---
![Accessdata_Dump_memory_for_malicious_process](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Accessdata_Dump_memory_for_malicious_process.png)
