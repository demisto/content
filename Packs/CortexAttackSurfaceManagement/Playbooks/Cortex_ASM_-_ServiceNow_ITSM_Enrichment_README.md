Given search terms, this playbook will query ServiceNow ticket descriptions and short descriptions over the last 30 days and set users that were found in the assigned_to field in those ServiceNow tickets. Note, the max amount of tickets returned from querying is 100.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

ServiceNow v2

### Scripts

* GridFieldSetup
* GetTime
* Set

### Commands

* servicenow-get-record
* servicenow-query-tickets

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| search_terms | Search terms to be used in the ServiceNow ITSM query search |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - ServiceNow ITSM Enrichment](../doc_files/Cortex_ASM_-_ServiceNow_ITSM_Enrichment.png)
