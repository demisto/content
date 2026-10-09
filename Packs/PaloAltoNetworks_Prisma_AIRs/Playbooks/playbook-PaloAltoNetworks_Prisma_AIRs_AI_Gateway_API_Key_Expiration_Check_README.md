Checks the expiration dates of the Prisma AIRS AI Gateway API keys (both service and user keys, across every workspace) for a single integration instance: lists the keys, buckets those that have an expiry into low/medium/high/critical risk by how many days remain until expiration, groups the keys by severity in context, reports each severity to the War Room as a table (most severe first), optionally emails when any key is more than medium risk, and closes the incident when there is nothing to remediate.

Flow - AI Gateway API keys are per-workspace, so the playbook first lists the workspaces, then lists the service and user API keys in each workspace (the workspace_id argument array-expands over the discovered workspaces). Keys that are active AND have an expiry set are kept; keys with no expiry (expires_at empty) are out of scope for expiration monitoring and are ignored. Each remaining key is placed in exactly one severity bucket by comparing its expires_at against the current time plus the tunable day thresholds - Critical (expires within CriticalWithinDays days, including already expired), High, Medium, and Low (everything further out). The thresholds are playbook inputs so the ranges can be tuned per use case. Each non-empty bucket is written to the War Room as a table, ordered most severe to least severe.

Email - an email is sent only when at least one key is more than medium risk (Critical or High) AND at least one recipient is configured. The email lists the offending keys grouped by severity, critical first.

Auto-close vs. manual close - when no key is Critical or High the incident closes automatically (closeReason "Resolved", closeNotes "Completed") so a recurring job leaves no open incidents. When at least one Critical or High key is found the playbook pauses on a manual "Validate remediation and approve to close" task so an analyst can rotate/renew the keys before the incident is closed.

Clone-per-tenant - every integration command is pinned to the instance named in the InstanceName input via the universal "using" argument, so this playbook can be duplicated and pointed at a different Prisma AIRS AI Gateway instance (tenant) without editing any task. Leave InstanceName empty to use the single enabled instance.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* PrismaAIRsAIGateway

### Scripts

* Set
* SetAndHandleEmpty
* ToTable

### Commands

* closeInvestigation
* prisma-airs-aigateway-api-keys-service-list
* prisma-airs-aigateway-api-keys-user-list
* prisma-airs-aigateway-workspaces-list
* send-mail

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InstanceName | The Prisma AIRS AI Gateway integration instance name to run every command against \(universal "using" argument\). Leave empty to use the single enabled instance. Set this \(and clone the playbook\) to check a different tenant. |  | Optional |
| PageSize | The maximum number of API keys to inventory per workspace \(passed to each list command's page_size argument\). Raise this if a workspace has more keys than the default. | 1000 | Optional |
| CriticalWithinDays | A key is Critical risk when it expires in fewer than this many days \(including already-expired keys\). Default 5 means 0-4 days remaining, or expired, is Critical. | 5 | Optional |
| HighWithinDays | A key is High risk when it expires in fewer than this many days but is not already Critical. Default 10 \(with CriticalWithinDays 5\) means 5-9 days remaining is High. | 10 | Optional |
| MediumWithinDays | A key is Medium risk when it expires in fewer than this many days but is not already High or Critical. Default 31 \(with HighWithinDays 10\) means 10-30 days remaining is Medium; anything further out is Low. | 31 | Optional |
| NotificationRecipients | Comma-separated email address\(es\) to notify when a key is more than medium risk. If left empty, no email is sent \(offenders are still reported to the War Room\). Requires a configured mail-sender integration on the tenant. |  | Optional |
| EmailSubjectPrefix | Prefix added to notification email subjects. Useful for per-tenant mailbox filtering. | [Prisma AIRS AI Gateway] | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayWorkspace | The workspaces discovered on the AI Gateway data plane. | unknown |
| PrismaAIRs.AIGatewayApiKey | The inventory of AI Gateway API keys \(service and user\) across all workspaces. | unknown |
| PrismaAIRs.AIGatewayApiKeyLive | The active AI Gateway API keys that have an expiry set \(the keys considered by the expiration check\). | unknown |
| PrismaAIRs.AIGatewayApiKeyCritical | The keys in the Critical risk bucket \(expiring within CriticalWithinDays days, or expired\). | unknown |
| PrismaAIRs.AIGatewayApiKeyHigh | The keys in the High risk bucket. | unknown |
| PrismaAIRs.AIGatewayApiKeyMedium | The keys in the Medium risk bucket. | unknown |
| PrismaAIRs.AIGatewayApiKeyLow | The keys in the Low risk bucket. | unknown |

## Playbook Image

---

![PaloAltoNetworks_Prisma_AIRs_AI_Gateway_API_Key_Expiration_Check](../doc_files/PaloAltoNetworks_Prisma_AIRs_AI_Gateway_API_Key_Expiration_Check.png)
