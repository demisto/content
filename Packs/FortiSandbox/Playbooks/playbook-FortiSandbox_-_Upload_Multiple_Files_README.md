Playbook used to upload files to FortiSandbox

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* FortiSandbox

### Scripts
This playbook does not use any scripts.

### Commands
* fortisandbox-upload-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileEntryID |  |  | Required |
| FileSHA256 |  |  | Required |
| ArchivePassword |  |  | Optional |
| VM-CSV-List |  |  | Optional |
| MalkPkg | Default is 0 |  | Optional |
| SkipSteps |  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
