This playbook unisolates endpoints according to the hostname/endpoint ID that is provided by the playbook input. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
FireEyeHXv2

### Scripts
IsIntegrationAvailable

### Commands
* fireeye-hx-get-host-information
* fireeye-hx-cancel-containment

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Endpoint_id | The endpoint ID/device ID that you want to unisolate. |  | Optional |
| Hostname | The hostname that you want to unisolate. | None | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![FireEye HX - Unisolate Endpoint](../doc_files/FireEye_HX_-_Unisolate_Endpoint.png)
