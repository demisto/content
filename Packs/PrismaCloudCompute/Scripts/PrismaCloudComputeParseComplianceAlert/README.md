Parse Compliance alert raw JSON data

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Prisma Cloud Compute |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Prisma Cloud Compute - Compliance Alert

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| alert_raw_json | The compliance alert raw JSON |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaCloudCompute.ComplianceAlert.compliance.description | The compliance description | String |
| PrismaCloudCompute.ComplianceAlert.compliance.id | The compliance ID | String |
| PrismaCloudCompute.ComplianceAlert.compliance.type | The compliance type | String |
| PrismaCloudCompute.ComplianceAlert.time | Compliance alert creation time | Date |
| PrismaCloudCompute.ComplianceAlert.type | Entity type \(host / image / container\) | String |
