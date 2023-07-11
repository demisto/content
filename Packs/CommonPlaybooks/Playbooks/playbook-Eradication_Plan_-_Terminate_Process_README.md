This playbook is one of the sub-playbooks in the eradication plan. 
This playbook handles the termination of the processes as a crucial step in the eradication action.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* Set

### Commands

* setParentIncidentContext
* core-run-script-kill-process
* core-get-script-execution-results

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ProcessTermination | Set to 'True' to terminate the process by path. | True | Optional |
| EndpointID | The endpoint ID to run commands over. |  | Optional |
| FilePath | The file path for the process termination. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Eradication Plan - Terminate Process](../doc_files/Eradication_Plan_-_Terminate_Process.png)
