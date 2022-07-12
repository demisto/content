This playbook is part of the 'Malware Investigation And Response' flow. For more information, please refer to https://xsoar.pan.dev/docs/reference/packs/malware-investigation-and-response.
This Playbook handles closing a true positive incident for Microsoft Defender for Endpoint.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
Microsoft Defender For Endpoint - Isolate Endpoint

### Integrations
MicrosoftDefenderAdvancedThreatProtection

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
| DupAlertIDsToBeClosed | The Cortex XSOAR investigation IDs to be closed.  |  | Optional |
| Comment | Add a comment to close an incident on the Microsoft Defender For Endpoint side. | XSOAR Incident #${incident.id} | Optional |
| Reason | Provide a reason for closing the incident. Choose one of the following:<br/>"NotAvailable"/"Apt,Malware"/"SecurityPersonnel"/"SecurityTesting"/"UnwantedSoftware"/"Other" |  | Optional |
| Classification | Choose From - "Unknown" / "TruePositive" / "FalsePositive" |  | Optional |
| TicketDescription | Specify the ticket description for this section.  |  | Optional |
| BlockTag | Specify the banning tag name for the found indicators. | BlockTag | Optional |
| TicketProjectName | If you are using Jira, specify the Jira Project Key here (can be retrieved from the Jira console). |  | Optional |
| TicketingSystemToUse | The name of the ticketing system to use, for example, Jira or ServiceNow. |  | Optional |
| AutoIsolation | Whether host isolation is allowed. | False | Optional |
| CloseDuplicate | Whether duplicate incidents should be closed as well in the Microsoft Defender for Endpoint integration instance.<br/>The playbook looks for the word "Close" in this input. |  | Optional |
| HostID | The ID of the host for running an isolation process. | ${incident.deviceid} | Optional |
| FileSha256 | Enter the File SHA256 you want to block. | ${incident.filesha256} | Optional |
| FileSha1 | Enter the File SHA1 you want to remove from your protected endpoints. | ${incident.filesha1} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - True Positive Incident Handling](../doc_files/MDE_-_True_Positive_Incident_Handling.png)
