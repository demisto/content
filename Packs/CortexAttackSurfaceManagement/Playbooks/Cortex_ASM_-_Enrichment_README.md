Used as a container folder for all enrichments of ASM alerts.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cortex ASM - AWS Enrichment
* Cortex ASM - Active Directory Enrichment
* Cortex ASM - Azure Enrichment
* Cortex ASM - Certificate Enrichment
* Cortex ASM - Cortex Endpoint Enrichment_Core_Combo
* Cortex ASM - Domain Enrichment
* Cortex ASM - GCP Enrichment
* Cortex ASM - On Prem Enrichment
* Cortex ASM - Prisma Cloud Enrichment
* Cortex ASM - Qualys Enrichment
* Cortex ASM - ServiceNow CMDB Enrichment
* Cortex ASM - ServiceNow ITSM Enrichment
* Cortex ASM - Splunk Enrichment
* Cortex ASM - Tenable.io Enrichment

### Integrations

* Cortex Attack Surface Management

### Scripts

* Sleep
* InferWhetherServiceIsDev
* GridFieldSetup

### Commands

* setAlert
* asm-get-external-service

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RemoteIP | IP address of service | alert.remoteip | Optional |
| AWSAssumeRoleName | If assuming roles for AWS, this is the name of the role to assume \(should be the same for all organizations\). |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ASM.ExternalService.externally_detected_providers | Providers of the external service. | unknown |

## Playbook Image

---

![Cortex ASM - Enrichment](../doc_files/Cortex_ASM_-_Enrichment.png)
