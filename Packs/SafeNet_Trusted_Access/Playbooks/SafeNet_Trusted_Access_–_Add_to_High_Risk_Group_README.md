This playbook adds the user to a group that was created to identify higher risk accounts. SafeNet Trusted Access policies can be configured to take this into account and provide stronger protection when handling access events from users who are members of the group. The user is added to this group for a configurable period of time.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SafeNetTrustedAccess

### Scripts
* SearchIncidentsV2
* PrintErrorEntry
* Sleep

### Commands
* setIncident
* sta-validate-tenant
* sta-get-user-info
* closeInvestigation
* sta-user-exist-group
* sta-remove-user-group
* sta-get-group-info
* sta-add-user-group

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| userName | Username of the user. | ${incident.safenettrustedaccessusername} | Required |
| highRiskGroup | Name of the High Risk Group. | ${lists.sta_high_risk_group} | Required |
| instanceName | Name of the SafeNet Trusted Access integration instance. | ${incident.safenettrustedaccessinstancename} | Required |
| sleepTime | Amount of time that the user will remain in the High Risk Group. | ${lists.sta_user_in_high_risk_group_hours} | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![SafeNet Trusted Access – Add to High Risk Group](./doc_files/SafeNet_Trusted_Access_–_Add_to_High_Risk_Group.png)