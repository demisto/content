This playbook unisolates endpoints according to the endpoint ID or hostname that is provided by the playbook input.
It currently supports the following integrations:
- Carbon Black Response
- Cortex XDR
- Crowdstrike Falcon
- FireEye HX 
- Cybereason


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Carbon Black Response - Unisolate Endpoint
* Unisolate Endpoint - Cybereason
* Crowdstrike Falcon - Unisolate Endpoint
* FireEye HX - Unisolate Endpoint
* Cortex XDR - Unisolate Endpoint

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
There are no outputs for this playbook.

## Playbook Image
---
![Unisolate Endpoint - Generic](https://raw.githubusercontent.com/demisto/content/4966d5a5c9b80af03106f8da8dcd8512b3cb259e/Packs/CommonPlaybooks/doc_files/Unisolate_Endpoint_-_Generic.png)
