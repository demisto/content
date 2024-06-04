Playbook to enrich certificate information.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* VenafiTLSProtect

### Scripts

* Set
* GridFieldSetup

### Commands

* venafi-get-certificates
* venafi-get-certificate-details

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Hostname | Input for Certificate enrichment | ${alert.hostname} | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Certificate Enrichment](../doc_files/Cortex_ASM_-_Certificate_Enrichment.png)
