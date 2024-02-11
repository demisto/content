Playbook to enriches Service ownership info in Azure and On-Prem Active Directory.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Microsoft Graph User
* Active Directory Query v2

### Scripts

* Set
* GridFieldSetup

### Commands

* msgraph-user-get
* ad-get-user

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| serviceowner | The service owner to enrich in Azure directory. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Active Directory Enrichment](../doc_files/Cortex_ASM_-_Active_Directory_Enrichment.png)
