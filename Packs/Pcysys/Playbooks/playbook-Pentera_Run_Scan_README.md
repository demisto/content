

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* pentera-run-template-by-name
* pentera-get-task-run-full-action-report
* pentera-get-task-run-status

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| PenteraTaskName | The name of the Pentera task to run |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Pentera.TaskRun.FullActionReport | Pentera Full Action Report is the summary of the given TaskName in a CSV format, that contains all the actions that Pentera performed during the task run. | unknown |

<!-- Playbook PNG image comes here -->