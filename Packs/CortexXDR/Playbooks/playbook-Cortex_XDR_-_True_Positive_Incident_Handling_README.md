This playbook is part of the 'Malware Investigation And Response' pack. For more information, refer to https://xsoar.pan.dev/docs/reference/packs/malware-investigation-and-response.
This playbook handles a true-positive incident closure for Cortex XDR - Malware Investigation.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex XDR - delete file
* Cortex XDR - Isolate Endpoint

### Integrations
CortexXDRIR

### Scripts
* ServiceNowCreateIncident
* IsIntegrationAvailable

### Commands
* setIndicators
* closeInvestigation
* jira-create-issue
* xdr-blocklist-files

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Comment | Add a comment to close this incident. | XSOAR Incident #${incident.id} | Optional |
| Classification | Possible values:<br/>* Unknown<br/>* TruePositive | TruePositive | Optional |
| BlockTag | The banning tag name for founded indicators. | BlockTag | Optional |
| AutoIsolation | Whether automatic host isolation is allowed. | False | Optional |
| TicketProjectName | The ticket project name (required for Jira). |  | Optional |
| TicketingSystemToUse | The name of the ticketing system to use, for example Jira or ServiceNow. |  | Optional |
| FileSha256 | The file SHA256 you want to block. | ${incident.filesha256} | Optional |
| HostID | The ID of the host for running an isolation process. | ${incident.deviceid} | Optional |
| FilePaths | The file paths you want to delete. | ${incident.processpath} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - True Positive Incident Handling](../doc_files/Cortex_XDR_-_True_Positive_Incident_Handling.png)
