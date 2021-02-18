Enriches Internal IP addresses using one or more integrations.

- Resolve IP address to hostname (DNS)
- Separate internal and external IP addresses
- Get host information for IP addresses

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Endpoint Enrichment - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* IPToHost
* IsIPInRanges

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| IP | The IP address to enrich. | Address | IP | Optional |
| InternalRange | A CSV list of IP address ranges (in CIDR notation). Use this list to check if an IP address is found within a set of IP address ranges. For example, "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" (without quotation marks). If no list is provided, the default list provided in the `IsIPInRanges` script (the known IPv4 private address ranges) will be used. | inputs.InternalRange | - | Optional |
| ResolveIP | Whether to convert the IP address to a hostname using a DNS query. Can be, "True" or "False" | None | inputs.ResolveIP | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IP | The IP objects. | unknown |
| DBotScore | The Indicator, Score, Type and Vendor. | unknown |
| Endpoint | The endpoint's object. | unknown |
| Endpoint.Hostname | The hostname to enrich. | string |
| Endpoint.OS | The Endpoint operating system. | string |
| Endpoint.IP | The list of endpoint IP addresses. | unknown |
| Endpoint.MAC | The list of endpoint MAC addresses. | unknown |
| Endpoint.Domain | The Endpoint domain name. | string |

## Playbook Image
---
![IP_Enrichment_Internal_Generic_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/IP_Enrichment_Internal_Generic_v2.png)
