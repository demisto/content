This playbook unisolates endpoints according to the endpoint ID that is provided in the playbook input.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
CortexXDR - IR

### Scripts
IsIntegrationAvailable

### Commands
* xdr-get-endpoints
* xdr-unisolate-endpoint

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Endpoint_ID | The endpoint ID that you want to unisolate. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - Unisolate Endpoint](https://raw.githubusercontent.com/demisto/content/4966d5a5c9b80af03106f8da8dcd8512b3cb259e/Packs/CortexXDR/doc_files/Cortex_XDR_-_Unisolate_Endpoint.png)
