Deprecated. Enriches IP addresses using one or more integrations.

IP enrichment includes:
* Resolve IP to Hostname (DNS)
* Threat information
* Separate internal and external addresses
* IP reputation
* For internal addresses, get host information

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Endpoint Enrichment - Generic

### Integrations
* VirusTotal - Private API

### Scripts
* IsIPInRanges
* IPToHost
* IPReputation

### Commands
* vt-private-get-ip-report

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| IP | The IP address to enrich. | Address | IP | Optional |
| InternalRange | The internal range to check against the IP address. The default range is taken from the IPv4 protocol. | - | - | Optional |
| ResolveIP | Convert the IP address to a hostname using a DNS query (True/False). | True | - | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IP | The IP address objects. | unknown |
| DBotScore | The Indicator, Score, Type, and Vendor. | unknown |
| Endpoint | The Endpoint's object. | unknown |
| Endpoint.Hostname | The hostname to enrich. | string |
| Endpoint.OS | The Endpoint OS. | string |
| Endpoint.IP | The list of Endpoint IP addresses. | unknown |
| Endpoint.MAC | The list of Endpoint MAC addresses. | unknown |
| Endpoint.Domain | The Endpoint domain name. | string |

## Playbook Image
---
![IP_Enrichment_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/IP_Enrichment_Generic.png)
