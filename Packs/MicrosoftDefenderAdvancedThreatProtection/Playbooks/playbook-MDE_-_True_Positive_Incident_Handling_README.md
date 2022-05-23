

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block Indicators - Generic v2
* Microsoft Defender For Endpoint - Isolate Endpoint

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
* ServiceNowCreateIncident
* SearchIncidentsV2
* IsIntegrationAvailable

### Commands
* jira-create-issue
* microsoft-atp-get-file-related-machines
* microsoft-atp-stop-and-quarantine-file
* closeInvestigation
* microsoft-atp-sc-indicator-create
* microsoft-atp-update-alert
* setIndicators

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DupAlertIDsToBeClosed | XSOAR Investigation IDs to be closed  |  | Optional |
| Comment | Add comment to close an incident on the Microsoft Defender For Endpoint side | XSOAR Incident #${incident.id} | Optional |
| Reason | Provide a reason for closing the incident. Please choose on of the following suggestions:<br/>"NotAvailable"/"Apt,Malware"/"SecurityPersonnel"/"SecurityTesting"/"UnwantedSoftware"/"Other" |  | Optional |
| Classification | Choose From - "Unknown" / "TruePositive" / "FalsePositive" |  | Optional |
| AllowTag | Specify the approving tag name for found indicators. |  | Optional |
| TicketDescription | Please Specify the ticket description for this section  |  | Optional |
| BlockTag | Specify the banning tag name for founded indicators. |  | Optional |
| JiraSummary | Enter the Jira Ticket Summary.<br/>Default: Cortex XSOAR - Malware Incident - \#$\{incident.id\} | Cortex XSOAR - Malware Incident - #${incident.id} | Optional |
| JiraTaskName | Enter Jira Task Name.<br/>Default: Malware Investigation - follow up \#$\{incident.id\} | Malware Investigation - follow up #${incident.id} | Optional |
| JiraProjectKey | Enter Jira Project Key. Can be seen in the Jira Project information.<br/> |  | Optional |
| TicketingSystemToUse |  |  | Optional |
| AutoIsolation | Indicates if host isolation is allowed.<br/>True/False |  | Optional |
| CloseDuplicate | Determine if the duplicate incidents should be closed as well in Microsoft Defender Instance.<br/>The playbook will look for the world "Close" in this input. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - True Positive Incident Handling](Insert the link to your image here)