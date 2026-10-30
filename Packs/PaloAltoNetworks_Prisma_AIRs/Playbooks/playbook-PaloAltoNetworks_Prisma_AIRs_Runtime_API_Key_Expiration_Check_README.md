Checks the expiration dates of the Prisma AIRS Runtime API keys for a single integration instance: lists the current (non-revoked) keys, buckets them into low/medium/high/critical risk by how many days remain until expiration, groups the keys by severity in context, reports each severity to the War Room as a table (most severe first), optionally emails when any key is more than medium risk, and closes the incident when there is nothing to remediate.

Flow - list the Runtime API keys and drop revoked keys. Each remaining key is placed in exactly one severity bucket by comparing its expires_at against the current time plus the tunable day thresholds - Critical (expires within CriticalWithinDays days, including already expired), High, Medium, and Low (everything further out). The thresholds are playbook inputs so the ranges can be tuned per use case. Each non-empty bucket is written to the War Room as a table, ordered most severe to least severe.

Email - an email is sent only when at least one key is more than medium risk (Critical or High) AND at least one recipient is configured. The email lists the offending keys grouped by severity, critical first.

Auto-close vs. manual close - when no key is Critical or High the incident closes automatically (closeReason "Resolved", closeNotes "Completed") so a recurring job leaves no open incidents. When at least one Critical or High key is found the playbook pauses on a manual "Validate remediation and approve to close" task so an analyst can rotate/renew the keys before the incident is closed.

Clone-per-tenant - every integration command is pinned to the instance named in the InstanceName input via the universal "using" argument, so this playbook can be duplicated and pointed at a different Prisma AIRS Runtime instance (tenant) without editing any task. Leave InstanceName empty to use the single enabled instance.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* PrismaAIRsRuntime

### Scripts

* Set
* SetAndHandleEmpty
* ToTable

### Commands

* closeInvestigation
* prisma-airs-runtime-api-keys-list
* send-mail

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InstanceName | The Prisma AIRS Runtime integration instance name to run every command against \(universal "using" argument\). Leave empty to use the single enabled instance. Set this \(and clone the playbook\) to check a different tenant. |  | Optional |
| MaxKeys | The maximum number of Runtime API keys to inventory \(passed to the list command's limit argument\). Raise this if a tenant has more keys than the default. | 1000 | Optional |
| CriticalWithinDays | A key is Critical risk when it expires in fewer than this many days \(including already-expired keys\). Default 5 means 0-4 days remaining, or expired, is Critical. | 5 | Optional |
| HighWithinDays | A key is High risk when it expires in fewer than this many days but is not already Critical. Default 10 \(with CriticalWithinDays 5\) means 5-9 days remaining is High. | 10 | Optional |
| MediumWithinDays | A key is Medium risk when it expires in fewer than this many days but is not already High or Critical. Default 31 \(with HighWithinDays 10\) means 10-30 days remaining is Medium; anything further out is Low. | 31 | Optional |
| NotificationRecipients | Comma-separated email address\(es\) to notify when a key is more than medium risk. If left empty, no email is sent \(offenders are still reported to the War Room\). Requires a configured mail-sender integration on the tenant. |  | Optional |
| EmailSubjectPrefix | Prefix added to notification email subjects. Useful for per-tenant mailbox filtering. | [Prisma AIRS Runtime] | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaAIRs.ApiKey | The inventory of Runtime API keys returned by the list step. | unknown |
| PrismaAIRs.RuntimeApiKeyLive | The non-revoked Runtime API keys considered by the expiration check. | unknown |
| PrismaAIRs.RuntimeApiKeyCritical | The keys in the Critical risk bucket \(expiring within CriticalWithinDays days, or expired\). | unknown |
| PrismaAIRs.RuntimeApiKeyHigh | The keys in the High risk bucket. | unknown |
| PrismaAIRs.RuntimeApiKeyMedium | The keys in the Medium risk bucket. | unknown |
| PrismaAIRs.RuntimeApiKeyLow | The keys in the Low risk bucket. | unknown |

## Playbook Image

---

![PaloAltoNetworks_Prisma_AIRs_Runtime_API_Key_Expiration_Check](../doc_files/PaloAltoNetworks_Prisma_AIRs_Runtime_API_Key_Expiration_Check.png)
