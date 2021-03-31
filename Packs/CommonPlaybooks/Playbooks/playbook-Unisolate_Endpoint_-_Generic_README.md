This playbook will auto Unisolate endpoints by the endpoint id that was provided in the playbook.
Currently supports the next integration:
- Carbon Black Response
- Cortex XDR
- Crowdstrike Falcon
- FireEye HX 
- Cybereason


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Unisolate Endpoint - Cybereason
* Cortex XDR - Unisolate Endpoint
* Crowdstrike Falcon - Unisolate Endpoint
* Carbon Black Response - Unisolate Endpoint
* FireEye HX - Unisolate Endpoint

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
| Endpoint_ID | The endpoint id/device id/sensor id/agent id that you wish to unisolate |  | Optional |
| Hostname | The hostname of the endpoint to unisolate using Cybereason. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Unisolate Endpoint - Generic](Insert the link to your image here)