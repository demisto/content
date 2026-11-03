Checks the health of the configured Prisma AIRS AI Gateway deployments (gateways) for a single integration instance, reports any unhealthy gateways to the War Room as a human-readable table, optionally emails a notification, and closes the incident when the run completes without errors (so it can be driven by a recurring job).

Flow - list the deployments on the AI Gateway admin plane (filtered by status, default active). Each returned deployment carries a connection_status field, which is the health signal. Filter the inventory down to the gateways whose connection_status indicates a definite problem (present, and not "healthy" or "unknown"; unknown/unset are treated as informational). When at least one unhealthy gateway is found, write the offenders to the War Room as a table and - when email notifications are enabled and at least one recipient is configured - send an email summary.

Auto-close vs. manual close - the healthy paths (no deployments found, or all gateways healthy) close the incident automatically (closeReason "Resolved", closeNotes "Completed") so a recurring job leaves no open incidents. The unhealthy path never auto-closes: it pauses on a manual "Validate remediation and approve to close" task so an analyst can investigate and confirm the fix before the incident is closed.

Clone-per-tenant - every integration command is pinned to the instance named in the InstanceName input via the universal "using" argument, so this playbook can be duplicated and pointed at a different Prisma AIRS AI Gateway instance (tenant) without editing any task. Leave InstanceName empty to use the single enabled instance.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* PrismaAIRsAIGateway

### Scripts

* SetAndHandleEmpty
* ToTable

### Commands

* closeInvestigation
* prisma-airs-aigateway-deployments-list
* send-mail

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InstanceName | The Prisma AIRS AI Gateway integration instance name to run every command against \(universal "using" argument\). Leave empty to use the single enabled instance. Set this \(and clone the playbook\) to check a different tenant. |  | Optional |
| StatusFilter | Which deployments to inventory and health-check. One of "active" or "archived". Defaults to active; archived gateways are intentionally disabled and are not treated as faults. | active | Optional |
| WorkspaceSlug | Optional comma-separated list of workspace slugs to narrow the deployment inventory. Leave empty to check all workspaces. |  | Optional |
| SendEmail | Master on/off switch for email notifications. One of "true" or "false". Email is sent only when this is true AND NotificationRecipients is non-empty AND at least one unhealthy gateway is found. | true | Optional |
| NotificationRecipients | Comma-separated email address\(es\) to notify. If left empty, no email is sent \(the unhealthy gateways are still reported to the War Room\). Requires a configured mail-sender integration on the tenant. |  | Optional |
| EmailSubjectPrefix | Prefix added to the notification email subject. Useful for per-tenant mailbox filtering. | [Prisma AIRS AI Gateway] | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayDeployment | The configured gateway deployments returned by the inventory step \(each row includes connection_status\). | unknown |
| PrismaAIRs.AIGatewayUnhealthy | The subset of deployments whose connection_status indicates a definite problem \(present, and not healthy or unknown\). | unknown |

## Playbook Image

---

![PaloAltoNetworks_Prisma_AIRs_AI_Gateway_Status_Check](../doc_files/PaloAltoNetworks_Prisma_AIRs_AI_Gateway_Status_Check.png)
