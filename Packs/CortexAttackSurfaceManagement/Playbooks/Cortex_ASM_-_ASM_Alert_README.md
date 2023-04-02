This playbook handles ASM alerts by enriching asset information and providing a means of remediating the issue directly or through contacting service owners.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cortex ASM - Detect Service
* Cortex ASM - Remediation
* Cortex ASM - Remediation Guidance
* Cortex ASM - Remediation Path Rules
* Cortex ASM - Enrichment

### Integrations

* ServiceNow v2

### Scripts

* GenerateASMReport
* GridFieldSetup
* GetTime

### Commands

* closeInvestigation
* send-mail
* servicenow-create-ticket

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| OwnerNotificationSubject | Subject of the notification \(email or ticket\) sent to potential service owner. | A new security risk was identified on an external service owned by your team | Required |
| OwnerNotificationBody | Body of the notification \(email or ticket\) sent to a potential service owner. | Infosec identified a security risk on an external service potentially owned by your team: ${alert.name}<br/><br/>Description: ${alert.details}<br/><br/> | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - ASM Alert](../doc_files/Cortex_ASM_-_ASM_Alert.png)
