This playbook remediates the following Prisma Cloud GCP VPC Network Project alerts.

Prisma Cloud policies remediated:

 - GCP project is using the default network

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Google Cloud Compute

### Scripts
* isError

### Commands
* gcp-compute-get-network
* gcp-compute-delete-network

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| policyId | Prisma Cloud policy Id. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
![Playbook Image](https://github.com/demisto/content/raw/master/Packs/PrismaCloud/doc_files/PCR_-_GCP_VPC_Network_Project_Misconfig.png)
