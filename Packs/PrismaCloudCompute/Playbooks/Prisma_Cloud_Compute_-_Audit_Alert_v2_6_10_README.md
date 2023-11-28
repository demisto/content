Default playbook for parsing and enrichment of Prisma Cloud Compute audit alerts.
The playbook has several sections:
Enrichment:
- Image details
- Similar container events
- Owner details
- Vulnerabilities
- Compliance details
- Forensics
- Defender logs

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Block Indicators - Generic v3
* Prisma Cloud Compute - Get Container Events
* Prisma Cloud - Get Account Owner
* Prisma Cloud Compute - Audit Alert Compliance Enrichment
* Prisma Cloud Compute - Get Defender Logs
* Prisma Cloud Compute - Container Forensics

### Integrations

* PaloAltoNetworks_PrismaCloudCompute

### Scripts

* PrismaCloudComputeParseAuditAlert
* SetAndHandleEmpty

### Commands

* setIncident
* prisma-cloud-compute-host-forensic-list
* createNewIndicator
* prisma-cloud-compute-defenders-list
* prisma-cloud-compute-profile-host-list
* closeInvestigation
* prisma-cloud-compute-images-scan-list

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| baseUrl | The base URL of the Prisma Cloud Compute Instance used to create a link back to the alerts for an image. | https://app.prismacloud.io | Optional |
| Project | A specific project name to get alert profiles for | PrismaCloudCompute.AlertProfiles.ServiceNow.Project | Optional |
| BlockIndicators | Whether to automatically block malicious indicators or not. | False | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Prisma Cloud Compute - Audit Alert v2](../doc_files/Prisma_Cloud_Compute_-_Audit_Alert_v2.png)
