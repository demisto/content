This playbook is used to pull information from Cortex Endpoint (XSIAM/XDR) systems for enrichment purposes.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Cortex Core - IR
* Cortex XDR - IR

### Scripts

* GridFieldSetup
* Set

### Commands

* core-get-endpoints
* xdr-get-endpoints
* extractIndicators

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RemoteIP | IP address of the service. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Cortex Endpoint Enrichment](../doc_files/Cortex_ASM_-_Cortex_Endpoint_Enrichment.png)
