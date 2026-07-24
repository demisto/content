# Cloudflare API

Integrates the Cloudflare API with Cortex, collecting Cloudflare account, security, and Zero
Trust Access activity into Cortex datasets, mapping it to the XDM data model, and detecting
account-takeover and configuration-abuse scenarios with correlation rules.

The pack follows a per-endpoint collector design: each Cloudflare API surface has its own event
collector and dataset, so log types can be modelled, retained, and correlated independently.

## Event collectors

| Collector | Source | Dataset |
| --- | --- | --- |
| Cloudflare Audit Logs Event Collector | `GET /accounts/{id}/audit_logs` (account and configuration activity) | `cloudflare_account_audit_raw` |
| Cloudflare Security Insights Event Collector | `GET /accounts/{id}/security-center/insights` (Security Center findings) | `cloudflare_security_insights_raw` |
| Cloudflare Access Authentication Logs Event Collector | `GET /accounts/{id}/access/logs/access_requests` (Zero Trust Access logins) | `cloudflare_access_auth_raw` |

The audit collector uses rolling high-water-mark collection. The Security Insights collector
takes periodic snapshots of current findings. The Access collector produces data only for
accounts that use Cloudflare Zero Trust Access.

## Detection content

The pack ships XDM modelling for the account audit and security insights datasets, and the
following correlation rules:

| Correlation | Detects | MITRE |
| --- | --- | --- |
| Cloudflare - API Token Created or Rolled | A new or rolled API token, a persistence vector after account compromise | TA0003 / T1098 |
| Cloudflare - Bulk DNS Record Deletion | An actor deleting many DNS records in a short window, a destructive or disruptive action | TA0040 / T1565 |
| Cloudflare - Security or Configuration Setting Changed | A change to a security or firewall setting | TA0005 / T1562 |
| Cloudflare - Security Posture Finding | A Security Center finding above an informational severity | Posture |

## Getting started

1. Create a Cloudflare **API Token** scoped to the account, with these permissions:
   **Account Settings - Read** (audit logs), **Account Security Center Insights - Read**
   (security insights), and **Access: Audit Logs - Read** (Access authentication logs).
2. Note your Cloudflare **Account ID**.
3. Configure an instance of each collector you want, providing the token and the account ID.
4. Events land in the datasets listed above and are mapped to XDM automatically.

## Datasets

- `cloudflare_account_audit_raw`: one event per audit-log record, `_time` from the record time.
- `cloudflare_security_insights_raw`: current Security Center findings, snapshot per fetch.
- `cloudflare_access_auth_raw`: one event per Zero Trust Access authentication (if Access is in use).

## Requirements

- A Cloudflare API Token with the permissions listed above. The endpoints are read-only.

## Licence

Licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
Copyright (c) GoCortexIO.
