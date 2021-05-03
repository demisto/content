Deprecated. Enrich IP using one or more integrations.

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
* IPToHost
* IPReputation
* IsIPInRanges

### Commands
* vt-private-get-ip-report

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | The IP address to enrich. | IP.Address | Optional |
| InternalRange | The internal range to check against the IP address.<br/>The default range is taken from the IPv4 protocol. |  | Optional |
| ResolveIP | Convert the IP address to a hostname using a DNS query \(True/ False\). | True | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IP | The IP objects | unknown |
| DBotScore | Indicator, Score, Type, Vendor | unknown |
| Endpoint | The Endpoint's object | unknown |
| Endpoint.Hostname | The hostname to enrich | string |
| Endpoint.OS | Endpoint OS | string |
| Endpoint.IP | List of endpoint IP addresses | unknown |
| Endpoint.MAC | List of endpoint MAC addresses | unknown |
| Endpoint.Domain | Endpoint domain name | string |

## Playbook Image
---
![IP Enrichment - Generic](Insert the link to your image here)