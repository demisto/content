Collects data using McAfee Active Response, from an endpoint for IR purposes (requires ePO as well).

Input:
* Hostname (Default: ${Endpoint.Hostname})

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* McAfee Active Response
* McAfee ePO v2

### Scripts
* Exists
* EPOFindSystem

### Commands
* mar-search-multiple
* epo-find-system

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | The hostname to run on. | ${Endpoint.Hostname} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MAR_Endpoint_data_collection](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/MAR_Endpoint_data_collection.png)
