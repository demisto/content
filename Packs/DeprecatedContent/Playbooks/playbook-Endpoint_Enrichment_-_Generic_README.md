Deprecated. Use "Endpoint Enrichment - Generic v2.1" playbook instead. Enrich an Endpoint Hostname using one or more integrations

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* CrowdStrike Endpoint Enrichment

### Integrations
* carbonblack
* SentinelOne
* Cylance Protect

### Scripts
* EPOFindSystem
* Exists
* ADGetComputer

### Commands
* cb-sensor-info
* cylance-protect-get-devices
* so-agents-query

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | The hostname to enrich | ${Endpoint.Hostname} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint | The Endpoint's object | unknown |
| Endpoint.Hostname | The hostname to enrich | string |
| Endpoint.OS | Endpoint OS | string |
| Endpoint.IP | List of endpoint IP addresses | unknown |
| Endpoint.MAC | List of endpoint MAC addresses | unknown |
| Endpoint.Domain | Endpoint domain name | string |

## Playbook Image
---
![Endpoint Enrichment - Generic](Insert the link to your image here)