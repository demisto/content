This Playbook handles a false-positive incident closure for Microsoft defender for endpoint 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Microsoft Defender For Endpoint - Unisolate Endpoint

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
* SearchIncidentsV2

### Commands
* closeInvestigation
* microsoft-atp-update-alert
* microsoft-atp-sc-indicator-create
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
| AutoUnisolation | Indicates if automatic un-isolation is allowed<br/>    True/False |  | Optional |
| CloseDuplicate | Determine if the duplicate incidents should be closed as well in Microsoft Defender Instance.<br/>The playbook will look for the world "Close" in this input. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - False Positive Incident Handling](Insert the link to your image here)