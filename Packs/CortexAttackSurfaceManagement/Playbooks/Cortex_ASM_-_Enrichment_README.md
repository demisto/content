Used as a container folder for all enrichments of ASM alerts.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex ASM - Tenable.io Enrichment
* Cortex ASM - ServiceNow CMDB Enrichment
* Cortex ASM - AWS Enrichment
* Cortex ASM - GCP Enrichment

### Integrations
* Cortex Attack Surface Management

### Scripts
This playbook does not use any scripts.

### Commands
* setAlert
* asm-get-external-service

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RemoteIP | IP address of service | alert.remoteip | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex ASM - Enrichment](../doc_files/Cortex_ASM_-_Enrichment.png)