This playbook remediates the following Prisma Cloud Azure SQL database alerts.

Prisma Cloud policies remediated:

- Azure SQL database auditing is disabled
- Azure SQL Database with Auditing Retention less than 90 days
- Azure Threat Detection on SQL databases is set to Off
- Azure SQL Database with Threat Retention less than or equals to 90 days

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Azure SQL Management

### Scripts
* IsIntegrationAvailable

### Commands
* azure-sql-db-threat-policy-create-update
* azure-sql-db-audit-policy-create-update

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
![Prisma Cloud Remediation - Azure SQL Database Misconfiguration](https://github.com/demisto/content/raw/master/Packs/PrismaCloud/doc_files/PCR_-_Azure_SQL_Database_Misconfig.png)
