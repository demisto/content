Given the IP address this playbook enriches information from Prisma Cloud.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Prisma Cloud - Find Public Cloud Resource by Public IP v2

### Integrations

This playbook does not use any integrations.

### Scripts

* GridFieldSetup

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| remoteIP | IP address of service. | alert.remoteip | Required |
| cloudProvider | Cloud service provider. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Prisma Cloud Enrichment](../doc_files/Cortex_ASM_-_Prisma_Cloud_Enrichment.png)
