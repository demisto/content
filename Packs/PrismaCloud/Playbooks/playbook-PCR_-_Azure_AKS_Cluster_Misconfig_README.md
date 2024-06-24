This playbook remediates the following Prisma Cloud Azure AKS cluster alerts.

Prisma Cloud policies remediated:

- Azure AKS cluster monitoring not enabled
- Azure AKS cluster HTTP application routing enabled

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Azure Kubernetes Services

### Scripts
* IsIntegrationAvailable

### Commands
* azure-ks-cluster-addon-update

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| policyId | Prisma Cloud policy Id. |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| incident.labels.resource.name | AKS cluster name. | string |

## Playbook Image
---
![Prisma Cloud Remediation - Azure AKS Cluster Misconfiguration](https://github.com/demisto/content/raw/master/Packs/PrismaCloud/doc_files/PCR_-_Azure_AKS_Cluster_Misconfig.png)
