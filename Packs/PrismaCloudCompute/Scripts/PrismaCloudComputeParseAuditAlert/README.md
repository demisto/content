Parse Audit alert raw JSON data

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

* Prisma Cloud Compute - Audit Alert

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| alert_raw_json | The compliance alert raw JSON |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaCloudCompute.AuditAlert.activityType | ActivityType is the type of the activity | String |
| PrismaCloudCompute.AuditAlert.appID | AppID is the RASP application ID | String |
| PrismaCloudCompute.AuditAlert.category | Category is the audit category | String |
| PrismaCloudCompute.AuditAlert.command | Command is the original \(with arguments\) command the user invoked | String |
| PrismaCloudCompute.AuditAlert.container | Container is the container name in which the alert occurred | String |
| PrismaCloudCompute.AuditAlert.forensicLink | ForensicLink is the link for downloading the forensic data for the related incident | String |
| PrismaCloudCompute.AuditAlert.fqdn | FQDN is the FQDN of the host in which the alert occurred | String |
| PrismaCloudCompute.AuditAlert.function | Function is the name of the serverless function which triggered the alert | String |
| PrismaCloudCompute.AuditAlert.host | Host is the host name in which the alert occurred | String |
| PrismaCloudCompute.AuditAlert.image | Image is the image name in which the alert occurred | String |
| PrismaCloudCompute.AuditAlert.interactive | Interactive indicates whether the alert belongs to an interactive session | Boolean |
| PrismaCloudCompute.AuditAlert.kubernetesResource | KubernetesResource is the resource name in which the alert occurred | String |
| PrismaCloudCompute.AuditAlert.line | Line is the matching log line | String |
| PrismaCloudCompute.AuditAlert.logfile | Logfile is the log file which was inspected | String |
| PrismaCloudCompute.AuditAlert.message | Message is the audit message | String |
| PrismaCloudCompute.AuditAlert.region | Region is the region of the serverless function | String |
| PrismaCloudCompute.AuditAlert.rule | Rule is the rule which triggered the alert | String |
| PrismaCloudCompute.AuditAlert.runtime | Runtime is the language runtime of the serverless function | String |
| PrismaCloudCompute.AuditAlert.service | Service is the owning systemd service | String |
| PrismaCloudCompute.AuditAlert.time | Time is the time when the alert occurred | Date |
| PrismaCloudCompute.AuditAlert.type | Type is the type of the audit alert | String |
| PrismaCloudCompute.AuditAlert.user | User is the user initiated the alert | String |
