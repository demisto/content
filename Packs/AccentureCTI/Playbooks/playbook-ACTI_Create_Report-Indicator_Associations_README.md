Creates associations between indicators and reports.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* CreateIndicatorRelationship
* GetIndicatorDBotScore
* Exists

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP |  | ${IP.Address} | Optional |
| IA |  | ${intelligence_alerts}.None | Optional |
| IR |  | ${intelligence_reports}.None | Optional |
| URL |  | ${URL.Data} | Optional |
| Domain |  | ${Domain.Name} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![ACTI Create Report-Indicator Associations](Insert the link to your image here)