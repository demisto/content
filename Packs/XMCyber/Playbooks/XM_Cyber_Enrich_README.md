Using either playbook input of IP or name or from the incident context this playbook enriches the incident with data from XM Cyber. Use this playbook as the default to handle new incidents related to devices/entities

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* XMCyber

### Scripts
* Exists
* ContextGetIps
* xmcyber-map
* IsTrue

### Commands
* xmcyber-version-supported
* hostname
* xmcyber-affected-entities-list
* xmcyber-affected-critical-assets-list
* ip
* xmcyber-entity-get

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | Name i.e. hostname | ${Endpoint.Hostname} | Optional |
| IpAddress | IP Address of entity to enrich | ${IP.Address} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| entityId | XMCyber Entity ID | string |
| isAsset | Is Entity a Critical Asset | boolean |

## Playbook Image
---
![XM Cyber Enrich](Insert the link to your image here)