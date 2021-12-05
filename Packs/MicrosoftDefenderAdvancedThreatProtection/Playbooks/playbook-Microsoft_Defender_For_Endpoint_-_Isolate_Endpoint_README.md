This playbook will auto isolate endpoints by the *device ID that was provided in the playbook.

*Hostname is not recognized as a device ID. 
For more information, you can use the following commands:
!microsoft-atp-get-machine-details
!microsoft-atp-get-machines

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
* SetAndHandleEmpty
* isError
* Print
* IsIntegrationAvailable

### Commands
* microsoft-atp-get-machine-details
* microsoft-atp-isolate-machine

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Device_id | The device ID to isolate.<br/>For more information, you can use the following commands:<br/>\!microsoft-atp-get-machine-details<br/>\!microsoft-atp-get-machines |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | The machine action ID. | unknown |
| MicrosoftATP.IsolateList | The Machine IDs which were Isolated | unknown |
| MicrosoftATP.NonIsolateList | Machine ID's which will not be isolated | unknown |

## Playbook Image
---
![Microsoft Defender For Endpoint - Isolate Endpoint](../doc_files/Microsoft_Defender_For_Endpoint_-_Isolate_Endpoint.png)