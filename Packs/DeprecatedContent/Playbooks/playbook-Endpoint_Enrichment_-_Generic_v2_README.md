Deprecated. Use "Endpoint Enrichment - Generic v2.1" playbook instead. Enrich an endpoint by hostname using one or more integrations.
Currently, the following integrations are supported:
- Active Directory
- McAfee ePolicy Orchestrator
- Carbon Black Enterprise Response
- Cylance Protect
- CrowdStrike Falcon Host

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* CrowdStrike Endpoint Enrichment

### Integrations
* epo
* Cylance Protect
* carbonblack

### Scripts
* ADGetComputer
* Exists

### Commands
* epo-find-system
* cylance-protect-get-devices
* cb-sensor-info

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | The hostname of the endpoint to enrich. | Endpoint.Hostname | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint | The endpoint object of the endpoint that was enriched. | unknown |
| Endpoint.Hostname | The hostnames of the endpoints that were enriched. | string |
| Endpoint.OS | The operating systems running on the endpoints that were enriched. | string |
| Endpoint.IP | A list of the IP addresses of the endpoints. | unknown |
| Endpoint.MAC | A list of the MAC addresses of the endpoints that were enriched. | unknown |
| Endpoint.Domain | The domain names of the endpoints that were enriched. | string |

## Playbook Image
---
![Endpoint Enrichment - Generic v2](Insert the link to your image here)