This playbook looks up MAC Leases using Infoblox NIOS integration.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* DeleteContext

### Commands

* infoblox-dhcp-lease-lookup
* infoblox-list-network-info

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| mac_addresses | The optional comma-separated list of MAC addresses to lookup. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![MAC Lease Lookup - Infoblox NIOS](../doc_files/MAC_Lease_Lookup_-_Infoblox_NIOS.png)
