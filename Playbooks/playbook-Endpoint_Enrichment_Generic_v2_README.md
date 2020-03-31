Enriches an endpoint by hostname using one or more integrations.

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
* Cylance Protect
* epo
* carbonblack

### Scripts
* ADGetComputer
* Exists

### Commands
* cb-sensor-info
* epo-find-system
* cylance-protect-get-devices

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| Hostname | The hostname of the endpoint to enrich. | Hostname | Endpoint | Optional |

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

![Endpoint_Enrichment_Generic_v2](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Endpoint_Enrichment_Generic_v2.png)
