This playbook will auto Isolate endpoints by the endpoint id that was provided in the playbook input.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* FireEyeHX

### Scripts
* IsIntegrationAvailable

### Commands
* fireeye-hx-get-host-information
* fireeye-hx-cancel-containment

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Endpoint_id | The endpoint id/device  id that  you wish to isolate. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![FireEye HX - Unisolate Endpoint](https://raw.githubusercontent.com/demisto/content/4966d5a5c9b80af03106f8da8dcd8512b3cb259e/Packs/FireEyeHX/doc_files/FireEye_HX_-_Unisolate_Endpoint.png)