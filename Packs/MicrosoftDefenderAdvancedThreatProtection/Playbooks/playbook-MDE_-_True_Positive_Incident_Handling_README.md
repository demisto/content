This Playbook handles a true-positive incident closure for Microsoft defender for endpoint

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Microsoft Defender For Endpoint - Isolate Endpoint

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
* SearchIncidentsV2
* IsIntegrationAvailable
* ServiceNowCreateIncident

### Commands
* jira-create-issue
* microsoft-atp-get-file-related-machines
* microsoft-atp-update-alert
* microsoft-atp-stop-and-quarantine-file
* setIndicators
* closeInvestigation
* microsoft-atp-sc-indicator-create

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DupAlertIDsToBeClosed | XSOAR Investigation IDs to be closed  |  | Optional |
| Comment | Add comment to close an incident on the Microsoft Defender For Endpoint side | XSOAR Incident #${incident.id} | Optional |
| Reason | Provide a reason for closing the incident. Please choose on of the following suggestions:<br/>"NotAvailable"/"Apt,Malware"/"SecurityPersonnel"/"SecurityTesting"/"UnwantedSoftware"/"Other" |  | Optional |
| Classification | Choose From - "Unknown" / "TruePositive" / "FalsePositive" |  | Optional |
| TicketDescription | Please Specify the ticket description for this section  |  | Optional |
| BlockTag | Specify the banning tag name for founded indicators. | BlockTag | Optional |
| TicketProjectName | In case you are using Jira, please specify the Jira Project Key here \( can be retrieved from the Jira console\) |  | Optional |
| TicketingSystemToUse | The name of the ticketing system to use, for example, Jira or ServiceNow |  | Optional |
| AutoIsolation | Indicates if host isolation is allowed.<br/>True/False | False | Optional |
| CloseDuplicate | Determine if the duplicate incidents should be closed as well in Microsoft Defender Instance.<br/>The playbook will look for the world "Close" in this input. |  | Optional |
| HostID | The ID of the host for running an isolation process. | ${incident.deviceid} | Optional |
| FileSha256 | Enter the File Sha256 you would like to block. | ${incident.filesha256} | Optional |
| FileSha1 | Enter the File Sha1 that you would like to remove from your protected endpoints. | ${incident.filesha1} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - True Positive Incident Handling](../doc_files/MDE_-_True_Positive_Incident_Handling.png)