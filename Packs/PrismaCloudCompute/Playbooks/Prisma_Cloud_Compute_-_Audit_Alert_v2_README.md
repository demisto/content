Default playbook for parsing Prisma Cloud Compute audit alerts.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* PaloAltoNetworks_PrismaCloudCompute

### Scripts

* ToTable
* CreatePrismaCloudComputeLink
* PrismaCloudComputeParseAuditAlert

### Commands

* prisma-cloud-compute-logs-defender
* prisma-cloud-compute-get-settings-defender
* findIndicators
* prisma-cloud-compute-profile-container-list
* setIncident
* prisma-cloud-compute-get-audit-firewall-container-alerts
* prisma-cloud-compute-logs-defender-download
* prisma-cloud-compute-get-waas-policies
* closeInvestigation
* prisma-cloud-compute-get-backups
* prisma-cloud-compute-get-alert-profiles
* prisma-cloud-compute-images-scan-list
* createNewIndicator
* prisma-cloud-compute-profile-container-forensic-list
* prisma-cloud-compute-profile-host-list

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| baseUrl | The base URL of the Prisma Cloud Compute Instance used to create a link back to the alerts for an image. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Prisma Cloud Compute - Audit Alert v2](../doc_files/Prisma_Cloud_Compute_-_Audit_Alert_v2.png)