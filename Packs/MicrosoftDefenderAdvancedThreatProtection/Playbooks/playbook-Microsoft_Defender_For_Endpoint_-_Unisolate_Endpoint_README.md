This playbook will auto unisolate endpoints through Microsoft Defender For Endpoint by using Hostname, IP, or Device ID associated with the asset you wish to block.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
* Print
* SetAndHandleEmpty
* isError
* IsIntegrationAvailable

### Commands
* microsoft-atp-get-machines
* microsoft-atp-unisolate-machine
* microsoft-atp-get-machine-details

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Device_id | The device ID to isolate.<br/>For more information, you can use the following commands:<br/>\!microsoft-atp-get-machine-details<br/>\!microsoft-atp-get-machines |  | Optional |
| Hostname | The Device Hostname that you would like to Isolate |  | Optional |
| Device_IP | The Device IP that you would like to Isolate |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | The machine action ID. | string |
| MicrosoftATP.NonUnisolateList | Those machine IDs that won't be released from isolation | string |
| MicrosoftATP.UnisolateList | Machine IDs that were released from isolation. | string |
| MicrosoftATP.IncorrectIDs | Incorrect Device IDs entered | string |
| MicrosoftATP.IncorrectHostnames | IncorrectHostnames entered | string |
| MicrosoftATP.IncorrectIPs | Incorrect Device IPs entered | string |

## Playbook Image
---
![Microsoft Defender For Endpoint - Unisolate Endpoint](../doc_files/Microsoft_Defender_For_Endpoint_-_Unisolate_Endpoint.png)