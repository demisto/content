Calculate and assign the incident severity based on the highest returned severity level from the following calculations:

Email security alert action
DBotScores of indicators
Critical assets
Email authenticity
Current incident severity
Microsoft Headers

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Calculate Severity - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* AssignAnalystToIncident
* IncreaseIncidentSeverity

### Commands
* send-mail
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Role | The default role to assign the incident to. |  | Optional |
| escalationRole | Higher Tier role to assign the incident to. |  | Optional |
| OnCall | Use to assign only for analysts who're on current shift. |  | Optional |
| AuthenticityCheck | Indicates the email authenticity resulting from the EmailAuthenticityCheck script. Possible values are: Pass, Fail, Suspicious, and Undetermined. |  | Optional |
| MicrosoftHeadersSeverityCheck | The value is set by the "Process Microsoft's Anti-Spam Headers" Playbook, which calculates the severity after processing the PCL, BCL and PCL values inside Microsoft's headers. |  | Optional |
| SOCEmailAddress | The SOC email address to set in case the playbook handles an Email Security alert. |  | Optional |
| EmailTo | The email recipient. |  | Optional |
| blockedAlertActionValue | List of optional values the email security device returns for blocked\\denied\\etc. emails. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Phishing Alerts - Check Severity](https://raw.githubusercontent.com/demisto/content/f49c8d86d18876948cd50ba32befb4f575420024/Packs/PhishingAlerts/doc_files/Phishing_Alerts_-_Check_Severity.png)