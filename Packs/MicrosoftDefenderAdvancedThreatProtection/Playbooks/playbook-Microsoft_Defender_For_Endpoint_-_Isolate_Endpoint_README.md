This playbook will auto isolate endpoints through Microsoft Defender For Endpoint by using Hostname,IP, or Device ID associated with the asset you wish to block.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
* isError
* Print
* SetAndHandleEmpty
* IsIntegrationAvailable

### Commands
* microsoft-atp-isolate-machine
* microsoft-atp-get-machines
* microsoft-atp-get-machine-details

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Device_id | The device ID to isolate.<br/>For more information, you can use the following commands:<br/>\!microsoft-atp-get-machine-details<br/>\!microsoft-atp-get-machines |  | Optional |
| Hostname | The Device Hostname that you would like to Isolate |  | Optional |
| Device_IP | The Device IP that you would like to Isolate |  | Optional |
| Isolation_type | Optional Values: Full/Selective. Default: Full<br/><br/>For more Information - Check Microsoft Documentation:<br/>  https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/respond-machine-alerts?view=o365-worldwide\#isolate-devices-from-the-network | Full | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | The machine action ID. | string |
| MicrosoftATP.IsolateList | The Machine IDs which were Isolated | string |
| MicrosoftATP.NonIsolateList | Machine ID's which will not be isolated | string |
| MicrosoftATP.IncorrectIDs | Incorrect Device IDs entered | string |
| MicrosoftATP.IncorrectHostnames | Incorrect Device Hostnames entered | string |
| MicrosoftATP.IncorrectIPs | Incorrect Device IPs entered | string |

## Playbook Image
---
![Microsoft Defender For Endpoint - Isolate Endpoint](../doc_files/Microsoft_Defender_For_Endpoint_-_Isolate_Endpoint.png)