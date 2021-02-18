Detonate one or more files using the FireEye Detection on Demand integration.  This playbook returns relevant reports to the War Room and file reputations to the context data.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* FireEye Detection on Demand

### Scripts
* Set

### Commands
* fireeye-dod-get-reports
* fireeye-dod-submit-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | File object of the file to detonate | ${File} | Optional |
| Interval | Polling frequency - how often the polling command should run \(minutes\) | 1 | Optional |
| Timeout | How much time to wait before a timeout occurs  \(minutes\) | 30 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The File object | unknown |

## Playbook Image
---
![Detonate File - FireEye Detection on Demand](../doc_files/playbook-Detonate_File_-_FireEye_Detection_on_Demand.png)