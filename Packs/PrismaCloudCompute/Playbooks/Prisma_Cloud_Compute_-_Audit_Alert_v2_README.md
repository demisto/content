Default playbook for parsing and enrichment of Prisma Cloud Compute audit alerts.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* PaloAltoNetworks_PrismaCloudCompute

### Scripts

* CreatePrismaCloudComputeLink
* PrismaCloudComputeParseAuditAlert
* ToTable

### Commands

* prisma-cloud-compute-get-alert-profiles
* prisma-cloud-compute-get-settings-defender
* prisma-cloud-compute-get-waas-policies
* prisma-cloud-compute-images-scan-list
* prisma-cloud-compute-get-audit-firewall-container-alerts
* prisma-cloud-compute-logs-defender-download
* prisma-cloud-compute-logs-defender
* setIncident
* prisma-cloud-compute-profile-container-forensic-list
* findIndicators
* closeInvestigation
* createNewIndicator
* prisma-cloud-compute-profile-host-list
* prisma-cloud-compute-profile-container-list
* prisma-cloud-compute-get-backups

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| baseUrl | The base URL of the Prisma Cloud Compute Instance used to create a link back to the alerts for an image. |  | Optional |
| Project | A specific project name to get alert profiles for | PrismaCloudCompute.AlertProfiles.ServiceNow.Project | Optional |
| Hostname | The Defender hostname | PrismaCloudCompute.AuditAlert.host | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Prisma Cloud Compute - Audit Alert v2](../doc_files/Prisma_Cloud_Compute_-_Audit_Alert_v2.png)
