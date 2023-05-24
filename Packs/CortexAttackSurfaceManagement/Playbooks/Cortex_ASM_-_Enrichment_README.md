Used as a container folder for all enrichments of ASM alerts.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cortex ASM - AWS Enrichment
* Cortex ASM - Azure Enrichment
* Cortex ASM - GCP Enrichment
* Cortex ASM - Prisma Cloud Enrichment
* Cortex ASM - Qualys Enrichment
* Cortex ASM - Rapid7 Enrichment
* Cortex ASM - Service Ownership
* Cortex ASM - ServiceNow CMDB Enrichment
* Cortex ASM - Splunk Enrichment
* Cortex ASM - Tenable.io Enrichment

### Integrations

* Cortex Attack Surface Management

### Scripts

* InferWhetherServiceIsDev

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