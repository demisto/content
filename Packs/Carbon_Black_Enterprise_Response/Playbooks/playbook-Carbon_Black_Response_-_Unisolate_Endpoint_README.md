This playbook will unisolate sensors in Carbon Black Response.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* integration-Carbon_Black_Enterprise_Response
* carbonblack-v2

### Scripts
* IsIntegrationAvailable

### Commands
* cb-sensor-info
* cb-list-sensors
* cb-unquarantine-device

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Endpoint_ID | The agent id/sensor id/endpoint id that you wish to unisolate.  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Carbon Black Response - Unisolate Endpoint](Insert the link to your image here)