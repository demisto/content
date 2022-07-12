This playbook is part of the 'Malware Investigation And Response' flow. For more information, please refer to https://xsoar.pan.dev/docs/reference/packs/malware-investigation-and-response.
This playbook handles a CrowdStrike incident that was determined to be a true positive by the analyst.  
Actions include isolating the host, blocking the indicator by the EDR, and tagging it.
  
## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
Crowdstrike Falcon - Isolate Endpoint

### Integrations
CrowdStrikeFalcon

### Scripts
* ServiceNowCreateIncident
* IsIntegrationAvailable

### Commands
* cs-falcon-resolve-detection
* cs-falcon-upload-custom-ioc
* cs-falcon-rtr-remove-file
* cs-falcon-resolve-incident
* jira-create-issue
* setIndicators

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TicketingSystemToUse | The name of the ticketing system to use, for example Jira or ServiceNow. |  | Optional |
| BlockIOCTagName | The tag to assign for indicators to block. |  | Optional |
| HostID | The ID of the host to use. |  | Optional |
| AutoIsolation | Whether automatic host isolation is allowed. | false | Optional |
| TicketProjectName | The ticket project name (required for Jira). |  | Optional |
| BlockMaliciousIOCGlobally | Whether adding to block list is global.<br/>If False, set the BlockHostGroup input to the group name. | True | Optional |
| BlockHostGroupName | The name of the allow list group to apply in case BlockMaliciousIOCGlobally is set to False. |  | Optional |
| TicketDescription | The description to be used by the ticketing system. |  | Optional |
| CloseNotes | Provide the close notes to be listed in CrowdStrike. |  | Optional |
| Sha256 | The SHA256 value to manage. |  | Optional |
| PathsForFilesToRemove | Provide the file path to remove from. |  | Optional |
| OperatingSystemToRemoveFrom | Possible values:<br/>* Windows<br/>* Linux<br/>* Mac<br/> |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![CrowdStrike Falcon - True Positive Incident Handling](../doc_files/CrowdStrike_Falcon_-_True_Positive_Incident_Handling.png)
