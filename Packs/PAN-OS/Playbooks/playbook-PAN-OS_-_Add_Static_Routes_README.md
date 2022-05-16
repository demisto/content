Accepts a PAN-OS static route configuration and creates it in the PAN-OS instance.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PanoramaCommitConfiguration

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* pan-os-list-static-routes
* pan-os-add-static-route

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| virtual_router_name | The name of the virtual router to configure the static routes for. | - |Required |
| route_name | The name to identify the static route (up to 31 characters). The name is case-sensitive and must be unique. The name can contain, letters, numbers, spaces, hyphens, and underscores. | - |Required |
| interface_name | The interface name where the static route will be added. | - |Optional |
| destination | The IP address and network mask in CIDR notation: ip_address/mask. For example, 192.168.2.0/24 for IPv4 or 2001:db8::/32 for IPv6. | - |Required |
| nexthop_type | The type for the nexthop. Can be, "ip-address", "next-vr", "fqdn" or "discard". | - |Required |
| nexthop_value | The next hop value. | - | Required |
| AutoCommit | Whether to auto-commit the configuration to PAN-OS. Can be, "Yes" or "No". | No |Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS_Add_Static_Routes](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PAN-OS_Add_Static_Routes.png)
