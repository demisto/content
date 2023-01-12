This playbook is part of the 'Malware Investigation And Response' pack. For more information, refer to https://xsoar.pan.dev/docs/reference/packs/malware-investigation-and-response.
This playbook handles closing false positive incidents for Microsoft Defender for Endpoint.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Microsoft Defender For Endpoint - Unisolate Endpoint

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
* SearchIncidentsV2

### Commands
* microsoft-atp-sc-indicator-create
* setIndicators
* microsoft-atp-update-alert
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DupAlertIDsToBeClosed | Duplicate Cortex XSOAR investigation IDs to close.  |  | Optional |
| Comment | Add a comment to close an incident on the Microsoft Defender for Endpoint side. | XSOAR Incident #${incident.id} | Optional |
| Reason | Provide a reason for closing the incident. Choose one of the following:<br/>"NotAvailable"/"Apt,Malware"/"SecurityPersonnel"/"SecurityTesting"/"UnwantedSoftware"/"Other" |  | Optional |
| Classification | Choose From - "Unknown" / "TruePositive" / "FalsePositive" |  | Optional |
| AllowTag | Specify the tag name for allowed indicators that are found. | AllowTag | Optional |
| AutoUnisolation | Whether automatic un-isolation is allowed. | False | Optional |
| CloseDuplicate | Whether the duplicate incidents should be closed as well in the Microsoft Defender for Endpoint instance.<br/>The playbook looks for the world "Close" in this input. |  | Optional |
| HostID | The ID of the host for running an un-isolation process. | ${incident.deviceid} | Optional |
| FileSha256 | Enter the File SHA256 you would like to block. | ${incident.filesha256} | Optional |
| GenerateAlert |  | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - Retrieve File](../doc_files/MDE_-_Retrieve_File.png)