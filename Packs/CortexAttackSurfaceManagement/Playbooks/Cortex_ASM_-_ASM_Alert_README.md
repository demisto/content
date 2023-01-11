This playbook handles ASM alerts by enriching asset information and providing a means of remediating the issue directly or through contacting service owners.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex ASM - Remediation
* Cortex ASM - Remediation Guidance
* Cortex ASM - Enrichment
* Cortex ASM - Detect Service

### Integrations
* ServiceNow v2

### Scripts
* GenerateASMReport
* GridFieldSetup
* GetTime

### Commands
* servicenow-create-ticket
* send-mail
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutomatedRemediation | Decide whether to potentially skip analyst intervention and conduct automated remediation if meeting the criteria specified here: https://cortex.marketplace.pan.dev/marketplace/details/CortexAttackSurfaceManagement/ <br/><br/>Default is "False" \(don't do automated remediation\).  Set "True" to turn this feature on. | False | Required |
| OwnerNotificationSubject | Subject of the notification \(email or ticket\) sent to potential service owner. | A new security risk was identified on an external service owned by your team | Required |
| OwnerNotificationBody | Body of the notification \(email or ticket\) sent to potential service owner. | Infosec identified a security risk on an external service potentially owned by your team: ${alert.name}&lt;br&gt;&lt;br&gt;<br/>Description: ${alert.details}<br/>&lt;br&gt;&lt;br&gt;<br/><br/> | Required |
| RemediationRule | The firewall rule that will be used for remediating internet exposures.  | Remediation-Security-Group | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex ASM - ASM Alert](../doc_files/Cortex_ASM_-_ASM_Alert.png)