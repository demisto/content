Main playbook to upload submissions to FortiSandbox, poll for verdict and retrieve report

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* b4900d98-bec2-48d5-80e0-c7c02974d5f1
* acad01ad-5822-4f4b-874a-1072e1e31521
* GenericPolling
* 6d811ef8-bbdf-45c7-8ceb-b21da95a3d36

### Integrations
* FortiSandbox

### Scripts
* Sleep

### Commands
* fortisandbox-get-pdf-report

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | Select Files to upload \(Provide File objects from upper playbook only if using this as a sub-playbook\). Change FileUploadLoop-FSBX to use $\{inputs.File.EntryID\} instead of $\{File.EntryID\}<br/> |  | Required |
| Retrieve PDF Report | If True will retrieve PDF report of Scan<br/>If False/Empty will not retrieve report | True | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.