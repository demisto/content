Collects endpoint information based on SentinelOne commands.

Input:
* Hostname (Default: ${Endpoint.Hostname})

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SentinelOne

### Scripts
* Print
* Exists

### Commands
* so-agents-query
* so-get-agent-processes

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** |  **Required** |
| --- | --- | --- | --- |  
| Hostname | The hostname of the device to run on. | ${Endpoint.Hostname} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
## Playbook Image
---
![Sentinel_One_Endpoint_data_collection](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Sentinel_One_Endpoint_data_collection.png)
