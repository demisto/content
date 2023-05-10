This playbook remediates Prisma Cloud Azure AKS alerts.  It calls sub-playbooks that perform the actual remediation steps.

Remediation:
- Azure AKS cluster monitoring not enabled
- Azure AKS cluster HTTP application routing enabled


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Prisma Cloud Remediation - Azure AKS Cluster Misconfiguration

### Integrations
* PrismaCloud v2

### Scripts
* IsIntegrationAvailable

### Commands
* closeInvestigation
* redlock-dismiss-alerts

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoRemediateAzureAKS | Execute Azure AKS remediation automatically? | no | Optional |
| policyId | Grab the Prisma Cloud policy Id. | incident.labels.policy | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| incident.labels.resource.name | AKS cluster name. | string |

## Playbook Image
---
![Prisma Cloud Remediation - Azure AKS Misconfiguration](https://github.com/demisto/content/raw/master/Packs/PrismaCloud/doc_files/PCR_-_Azure_AKS_Misconfig.png)
