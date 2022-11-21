Used as a container folder for all enrichments of ASM alerts.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* AWS - Enrichment
* ServiceNow CMDB Search

### Integrations
* ServiceNow v2
* Cortex Attack Surface Management

### Scripts
* GridFieldSetup
* GetTime

### Commands
* asm-list-external-service
* servicenow-query-users

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RemoteIP | IP address of the service. | alert.remoteip | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex ASM - Enrichment](../doc_files/Cortex_ASM_-_Enrichment.png)
