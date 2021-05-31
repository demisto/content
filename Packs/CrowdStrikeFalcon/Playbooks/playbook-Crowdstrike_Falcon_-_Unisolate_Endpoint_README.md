This playbook unisolates devices according to the device ID that is provided in the playbook input.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
CrowdStrikeFalcon

### Scripts
IsIntegrationAvailable

### Commands
* cs-falcon-lift-host-containment
* cs-falcon-search-device

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Endpoint_id | The endpoint ID/device ID that you want to unisolate.  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Crowdstrike Falcon - Unisolate Endpoint](https://raw.githubusercontent.com/demisto/content/4966d5a5c9b80af03106f8da8dcd8512b3cb259e/Packs/CrowdStrikeFalcon/doc_files/Crowdstrike_Falcon_-_Unisolate_Endpoint.png)
