This playbook executes a job and exits when it successfully finishes.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Rundeck

### Scripts
This playbook does not use any scripts.

### Commands
* rundeck-job-execute

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| job_id | ID of the job to execute. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Rundeck-job-execute-Generic](../doc_files/Rundeck-job-execute-Generic.png)