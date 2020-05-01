Enriches IP addresses using one or more integrations.

- Resolve IP addresses to hostnames (DNS)
- Provide threat information
- Separate internal and external IP addresses
- For internal IP addresses, get host information

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* IP Enrichment - Internal - Generic v2
* IP Enrichment - External - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| IP | The IP address to enrich. | Address | IP | Optional |
| InternalRange | A list of internal IP address ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" (without quotation marks). If a list is not provided, the default list provided in the `IsIPInRanges` script (the known IPv4 private address ranges). | None | inputs.InternalRange | Optional |
| ResolveIP | Determines whether to convert the IP address to a hostname using a DNS query (True/False). | None | inputs.ResolveIP | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IP | The IP objects. | unknown |
| DBotScore | The Indicator, Score, Type, and Vendor. | unknown |
| Endpoint | The Endpoint's object. | unknown |
| Endpoint.Hostname | The hostname to enrich. | string |
| Endpoint.OS | The Endpoint OS. | string |
| Endpoint.IP | The list of Endpoint IP addresses. | unknown |
| Endpoint.MAC | The list of Endpoint MAC addresses. | unknown |
| Endpoint.Domain | The Endpoint domain name. | string |

## Playbook Image
---
![IP_Enrichment_Generic_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/IP_Enrichment_Generic_v2.png)
