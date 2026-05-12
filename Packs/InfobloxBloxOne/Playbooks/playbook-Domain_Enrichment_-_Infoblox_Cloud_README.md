This playbook enriches domains or hosts with the dossier, TIDE and asset data using Infoblox Threat Defense with DDI integration.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* InfobloxBloxOneThreatDefense

### Scripts

* DeleteContext

### Commands

* bloxone-td-dossier-lookup-get
* domain
* findIndicators

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| domains | The optional comma-separated list of domains or hosts to enrich. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Domain Enrichment - Infoblox Cloud](../doc_files/Domain_Enrichment_-_Infoblox_Cloud.png)
