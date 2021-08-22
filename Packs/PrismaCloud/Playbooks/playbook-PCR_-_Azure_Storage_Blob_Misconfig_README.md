This playbook remediates the following Prisma Cloud Azure Storage blob alerts.

Prisma Cloud policies remediated:

- Azure storage account has a blob container with public access
- Azure storage account logging for blobs is disabled


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Azure Storage

### Scripts
* IsIntegrationAvailable

### Commands
* azure-storage-account-create-update

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| policyId | Prisma Cloud policy Id. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Prisma Cloud Remediation - Azure Storage Blob Misconfiguration](https://github.com/demisto/content/raw/master/Packs/PrismaCloud/doc_files/PCR_-_Azure_Storage_Blob_Misconfig.png
