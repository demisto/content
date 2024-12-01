This playbook will auto isolate endpoints by the endpoint ID that was provided in the playbook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
FireEyeHXv2

### Scripts
IsIntegrationAvailable

### Commands
* fireeye-hx-host-containment
* fireeye-hx-get-host-information

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Endpoint_id | The endpoint ID or device ID to isolate. |  | Optional |
| Hostname | The hostname to isolate. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![FireEye HX - Isolate Endpoint ](../doc_files/FireEye_HX_-_Isolate_Endpoint.png)
