This playbook edits rules with unused applications or rules that are port based, and adds an application to the rule. It is used in PAN-OS - Policy Optimizer playbooks and includes communication tasks to get a rule name and the application to edit from the user.

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
panorama-edit-rule

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| rules_list | PAN-OS rules to edit using the playbook. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RulesToEdit | Policy rules to edit using the playbook. | String |

## Playbook Image
---
![Policy Optimizer - Add Applications to Policy Rules](https://github.com/demisto/content/raw/82df056cff9dc4ce8b0753b341a4434593fa4608/Packs/PANOSPolicyOptimizer/doc_files/Policy_Optimizer_-_Add_Applications_to_Policy_Rules.png?raw=true)
