Used as a container folder for all enrichments of ASM alerts.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex ASM - Tenable.io Enrichment
* 3a1ae341-bbe0-4da9-85f1-527b508efd74
* Cortex ASM - ServiceNow CMDB Enrichment
* Cortex ASM - Rapid7 Enrichment
* Cortex ASM - AWS Enrichment
* 56d132cf-462f-4495-8a8e-3c7e8b8fc829
* Cortex ASM - Azure Enrichment
* Cortex ASM - Splunk Enrichment
* Cortex ASM - Service Ownership

### Integrations
* Cortex Attack Surface Management

### Scripts
* InferWhetherServiceIsDev
* IdentifyServiceOwners

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

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ASM.ExternalService.externally_detected_providers | Providers of the external service. | unknown |

## Playbook Image
---
![Cortex ASM - Enrichment](../doc_files/Cortex_ASM_-_Enrichment.png)