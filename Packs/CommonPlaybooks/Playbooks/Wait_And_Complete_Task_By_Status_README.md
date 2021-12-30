Waits for a task to reach a certain status, and/or completes the task. The playbook should be used in a loop until the FoundTaskNames context key contains the name of the awaited task (the playbook outputs that name).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* DemistoGetIncidentTasksByState

### Commands
* taskComplete

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TaskStates | Comma separated list of states. Possible values: New, InProgress, Completed, Waiting, Error, Skipped, Blocked \(leave empty to get all tasks\) |  | Optional |
| CompleteOption | The path to take in conditional tasks. For example, if your conditional task has "Yes" or "No", a possible value here may be "Yes". |  | Optional |
| IncidentID | The ID of the incident where the task should be completed. |  | Required |
| TaskName | Optional - the name of the task that should be completed. |  | Optional |
| CompleteTask | Whether to also complete the task, or just check if it's completed. Can be True or False. | True | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| FoundTaskNames | The names of the tasks that were found and completed. | unknown |

## Playbook Image
---
![Wait And Complete Task By Status](Insert the link to your image here)