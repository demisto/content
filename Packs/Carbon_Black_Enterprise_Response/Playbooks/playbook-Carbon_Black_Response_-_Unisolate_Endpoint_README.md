This playbook unisolates sensors according to the sensor ID that is provided in the playbook input.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
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
| Endpoint_ID | The sensor id you want to unisolate.  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Carbon Black Response - Unisolate Endpoint](https://raw.githubusercontent.com/demisto/content/4966d5a5c9b80af03106f8da8dcd8512b3cb259e/Packs/Carbon_Black_Enterprise_Response/doc_files/Carbon_Black_Response_-_Unisolate_Endpoint.png)
