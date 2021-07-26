Send Indicators playbook is used to create or update threat indicators in Cofense Triage that have been identified as malicious or suspicious by the analysis.

Users are only able to run the playbook in v6.0.0 or higher as it requires commands to execute the task.
## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* cofense-threat-indicator-create
* cofense-threat-indicator-list
* cofense-threat-indicator-update

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Value | The indicator value. |  | Required |
| Level | Represents the status of the indicator. |  | Required |
| Type | Type of the indicator. |  | Required |
| Source | The source reporting the indicator. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image

![Send Indicators - Cofense Triage v3](./../doc_files/Send_Indicators_-_Cofense_Triage_v3.png)