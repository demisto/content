This playbook will auto Isolate endpoints by the endpoint id that was provided in the playbook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* FireEyeHX

### Scripts
* IsIntegrationAvailable

### Commands
* fireeye-hx-host-containment
* fireeye-hx-get-host-information

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Endpoint_id | The endpoint id/device  id that  you wish to isolate. |  | Optional |
| Hostname | the hostname that you wish to isolate. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![FireEye HX - Isolate Endpoint ](Insert the link to your image here)