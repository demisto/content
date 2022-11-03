This playbook aims to handle ASM alerts by enriching asset information and providing means of remediating the issue directly or through contacting service owners.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex ASM - Detect Service
* Cortex ASM - Enrichment
* AWS - Security Group Remediation
* Cortex ASM - Remediation Guidance

### Integrations
* ServiceNow v2

### Scripts
* GridFieldSetup
* GetTime
* GenerateASMReport

### Commands
* servicenow-create-ticket
* closeInvestigation
* send-mail

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutomatedRemediation | Decide whether to potential skip analyst intervention and conduct automated remediation if meeting the following criteria: issue is Insecure OpenSSH/RDP, happened on EC2 instance, service owner information found and indicators of a non-prod host.  Default if "False" \(don't do automated remediation\).  Set "True" to turn this feature on. | False | Required |
| OwnerNotificationSubject | Subject of the notification \(email or ticket\) send to potential service owner. | A new security risk was identified on an external service owned by your team | Required |
| OwnerNotificationBody | Body of the notification \(email or ticket\) send to potential service owner. | Infosec identified a security risk on an external service potentially owned by your team: ${alert.name}<br/><br/>Description: ${alert.details}<br/><br/> | Required |
| RemediationRule | The firewall rule that will used for remediating internet exposures.  | Remediation-Security-Group | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex ASM - ASM Alert](../doc_files/Cortex_ASM_-_ASM_Alert.png)