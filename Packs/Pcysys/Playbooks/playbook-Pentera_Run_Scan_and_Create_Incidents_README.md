This playbook will run a pentera task given the Pentera task name. It will generate the full action report that contains all the actions that Pentera made during the scan, and will create incidents according to the filters in the Pentera Filter and Create incidents playbook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Pentera Run Scan
* Pentera Filter And Create Incident

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| PenteraTaskName | The name of the Pentera task to run. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->