This playbook enriches MAC addresses with DHCP lease information using Infoblox Threat Defense with DDI integration.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* DeleteContext

### Commands

* infobloxcloud-mac-enrich

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| mac_addresses | The comma-separated list of MAC addresses to enrich. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![MAC Enrichment - Infoblox Cloud](../doc_files/MAC_Enrichment_-_Infoblox_Cloud.png)
