Given inputs of an Endpoint indicator, this playbook will enrich with data from XM. This is a simpler and less robust playbook than the XM Cyber Enrich affected assets, entities, etc

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* XMCyber

### Scripts
* IsTrue
* xmcyber-map

### Commands
* xmcyber-affected-entities-list
* xmcyber-affected-critical-assets-list
* xmcyber-entity-get
* xmcyber-version-supported

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | The hostname to enrich | ${Endpoint.Hostname} | Optional |
| IPAddress | IP address of entity | ${Endpoint.IPAddress} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint.ID | Unique ID of the endpoint in FalconHost | string |
| Endpoint.IPAddress | IPAddress of the endpoint | string |
| Endpoint.Domain | Domain of the endpoint | string |
| Endpoint.MACAddress | MACAddress of the endpoint | string |
| Endpoint.OS | OS of the endpoint | string |
| Endpoint.OSVersion | OSVersion of the endpoint | string |
| Endpoint.BIOSVersion | BIOSVersion of the endpoint | string |
| Endpoint.HostName | The host of the endpoint | string |

## Playbook Image
---
![XM Cyber Endpoint Enrichment](Insert the link to your image here)