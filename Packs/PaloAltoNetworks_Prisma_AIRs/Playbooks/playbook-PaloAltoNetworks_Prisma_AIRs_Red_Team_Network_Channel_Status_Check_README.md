Checks the health of the Prisma AIRS Red Team network broker channels for a single integration instance: flags any offline channels and any online channels whose connected clients are running an outdated version, reports the offenders to the War Room as human-readable tables, optionally emails notifications, and closes the incident when there is nothing to remediate.

Flow - pull the deployment statistics (current client_version and online/total counts) and list every network channel. Offline channels (status OFFLINE) are treated as a problem; DRAFT ("not yet completed") channels are informational and are not alerted. Channels with at least one outdated connected client (outdated_clients_count >= 1) are treated as a problem; the report shows each channel's oldest_client_version and the current client_version to upgrade to. Each check is independently gated by an input (NotifyOffline / NotifyOutdated) so you can tune what the playbook investigates and alerts on.

Auto-close vs. manual close - when nothing needs remediation the incident closes automatically (closeReason "Resolved", closeNotes "Completed") so a recurring job leaves no open incidents. When at least one offline or outdated problem is found the playbook pauses on a manual "Validate remediation and approve to close" task so an analyst can confirm the fix before the incident is closed.

Clone-per-tenant - every integration command is pinned to the instance named in the InstanceName input via the universal "using" argument, so this playbook can be duplicated and pointed at a different Prisma AIRS Red Team instance (tenant) without editing any task. Leave InstanceName empty to use the single enabled instance.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* PrismaAIRsRedTeam

### Scripts

* SetAndHandleEmpty
* ToTable

### Commands

* closeInvestigation
* prisma-airs-redteam-network-channels-list
* prisma-airs-redteam-network-channels-stats
* send-mail

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InstanceName | The Prisma AIRS Red Team integration instance name to run every command against \(universal "using" argument\). Leave empty to use the single enabled instance. Set this \(and clone the playbook\) to check a different tenant. |  | Optional |
| MaxChannels | The maximum number of network channels to inventory \(passed to the list command's limit argument\). Raise this if a tenant has more channels than the default. | 1000 | Optional |
| NotifyOffline | Whether to investigate and alert on offline channels. One of "true" or "false". When false, offline channels are ignored and never block auto-close. | true | Optional |
| NotifyOutdated | Whether to investigate and alert on channels with outdated connected clients. One of "true" or "false". When false, outdated clients are ignored and never block auto-close. | true | Optional |
| NotificationRecipients | Comma-separated email address\(es\) to notify. If left empty, no email is sent \(offenders are still reported to the War Room\). Requires a configured mail-sender integration on the tenant. |  | Optional |
| EmailSubjectPrefix | Prefix added to notification email subjects. Useful for per-tenant mailbox filtering. | [Prisma AIRS Red Team] | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaAIRs.RedTeamNetworkChannelStats | The network channel deployment statistics \(current client_version, online/total counts, deployment info\). | unknown |
| PrismaAIRs.RedTeamNetworkChannel | The inventory of network broker channels returned by the list step. | unknown |
| PrismaAIRs.RedTeamOfflineChannel | The subset of channels whose status is OFFLINE. | unknown |
| PrismaAIRs.RedTeamOutdatedChannel | The subset of channels with at least one connected client running an outdated version. | unknown |

## Playbook Image

---

![PaloAltoNetworks_Prisma_AIRs_Red_Team_Network_Channel_Status_Check](../doc_files/PaloAltoNetworks_Prisma_AIRs_Red_Team_Network_Channel_Status_Check.png)
