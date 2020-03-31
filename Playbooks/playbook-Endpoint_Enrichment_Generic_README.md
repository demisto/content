Enriches an Endpoint hostname using one or more integrations.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* CrowdStrike Endpoint Enrichment

### Integrations
* carbonblack
* SentinelOne
* Cylance Protect

### Scripts
* Exists
* ADGetComputer
* EPOFindSystem

### Commands
* so-agents-query
* cb-sensor-info
* cylance-protect-get-devices

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | The hostname to enrich. | ${Endpoint.Hostname} |Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint | The Endpoint's object. | unknown |
| Endpoint.Hostname | The hostname to enrich. | string |
| Endpoint.OS | The Endpoint OS. | string |
| Endpoint.IP | The list of Endpoint IP addresses. | unknown |
| Endpoint.MAC | The list of Endpoint MAC addresses. | unknown |
| Endpoint.Domain | The Endpoint domain name. | string |

![Endpoint_Enrichment_Generic](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Endpoint_Enrichment_Generic.png)
