This playbook unisolates endpoints according to the endpoint ID that is provided in the playbook input.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CortexXDRIR

### Scripts
* IsIntegrationAvailable

### Commands
* xdr-endpoint-unisolate
* xdr-get-endpoints

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Endpoint_ID | The endpoint ID that you want to be unisolated. |  | Optional |
| Hostname | The endpoint's hostname that you want to be unisolated. |  | Optional |
| IP | The endpoint's IP that you want to be unisolated. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - Unisolate Endpoint](../doc_files/Cortex_XDR_-_Unisolate_Endpoint6_2.png)