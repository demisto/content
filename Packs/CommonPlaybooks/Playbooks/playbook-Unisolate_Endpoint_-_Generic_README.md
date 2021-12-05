This playbook unisolates endpoints according to the endpoint ID or hostname that is provided in the playbook.
Currently supports the following integrations:
- Carbon Black Response
- Cortex XDR
- Crowdstrike Falcon
- FireEye HX 
- Cybereason
- Microsoft Defender For Endpoint

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Unisolate Endpoint - Cybereason
* FireEye HX - Unisolate Endpoint
* Carbon Black Response - Unisolate Endpoint
* Cortex XDR - Unisolate Endpoint
* Microsoft Defender For Endpoint - Unisolate Endpoint
* Crowdstrike Falcon - Unisolate Endpoint

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Endpoint_ID | The endpoint id/device id/sensor id/agent id that you want to unisolate. |  | Optional |
| Hostname | The hostname of the endpoint to unisolate \(using Cybereason or FireEyeHX\). |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | The machine action ID. | unknown |
| MicrosoftATP.NonUnisolateList | Those machine IDs that won't be released from isolation | unknown |
| MicrosoftATP.UnisolateList | Machine IDs that were released from isolation. | unknown |

## Playbook Image
---
![Unisolate Endpoint - Generic](../doc_files/Unisolate_Endpoint_-_Generic.png)