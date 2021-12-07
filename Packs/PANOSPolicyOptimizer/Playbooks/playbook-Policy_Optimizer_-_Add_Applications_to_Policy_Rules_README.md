This playbook is used in the PAN-OS - Policy Optimizer playbooks to edit rules with unused applications or rules that are port based, and add an application to the rule.
The playbook uses communication task to get a rule name and the application to edit from the user.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* SetAndHandleEmpty
* DeleteContext
* IsIntegrationAvailable

### Commands
* panorama-edit-rule

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| rules_list | PAN-OS rules to edit using the playbook. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RulesToEdit | Policy rules to edit using the playbook. | string |

## Playbook Image
---
![Policy Optimizer - Add Applications to Policy Rules](Insert the link to your image here)