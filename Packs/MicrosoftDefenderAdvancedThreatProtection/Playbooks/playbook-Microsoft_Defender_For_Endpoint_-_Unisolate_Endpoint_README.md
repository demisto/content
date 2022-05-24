This playbook accepts an endpoint ID, IP, or host name and unisolates it using the Microsoft Defender For Endpoint integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
* SetAndHandleEmpty
* isError
* IsIntegrationAvailable
* Print

### Commands
* endpoint
* microsoft-atp-unisolate-machine

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Device_id | The device ID to isolate.<br/>For more information about the device, you can use the following commands:<br/>\!microsoft-atp-get-machine-details<br/>\!microsoft-atp-get-machines |  | Optional |
| Hostname | The device host name you want to isolate. |  | Optional |
| Device_IP | The device IP you want to isolate. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | The machine action ID. | string |
| MicrosoftATP.NonUnisolateList | The machine IDs that will not be released from isolation. | string |
| MicrosoftATP.UnisolateList | The machine IDs that were released from isolation. | string |
| MicrosoftATP.IncorrectIDs | Incorrect device IDs entered. | string |
| MicrosoftATP.IncorrectHostnames | Incorrect host names entered. | string |
| MicrosoftATP.IncorrectIPs | Incorrect device IPs entered. | string |

## Playbook Image
---
![Microsoft Defender For Endpoint - Unisolate Endpoint](../doc_files/Microsoft_Defender_For_Endpoint_-_Unisolate_Endpoint.png)