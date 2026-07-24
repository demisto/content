# Cloudflare Audit Logs Event Collector

Collect account audit logs from Cloudflare and ingest them into Cortex XSIAM.

This integration was integrated and tested with the Cloudflare API v4 `audit_logs` endpoint.

## Required API token permission

Create a Cloudflare **API Token** with the **Account Settings > Read** permission. In the token
editor (My Profile > API Tokens > your token > Edit), under **Permissions** set the three
dropdowns to:

1. **Account**
2. **Account Settings**
3. **Read**

Scope the token to the account(s) you want to collect from (Account Resources > your account).

> **Important:** use **Account Settings: Read**, *not* **"Access: Audit Logs Read"**. The latter is
> for Cloudflare Access (Zero Trust) authentication logs, not the account audit trail. A token with
> only that permission returns `403 Authentication error (code 10000)`.

## Configure Cloudflare Audit Logs Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Cloudflare API base URL. | True |
| API Token | A Cloudflare API Token with the **Account Settings &gt; Read** permission (not "Access: Audit Logs"). | True |
| Account IDs | A comma-separated list of Cloudflare account IDs. | True |
| First fetch time | The time range to fetch on the first run (e.g. `3 days`). | False |
| Maximum number of events per account per fetch | Upper bound of events pulled per account each run. | False |
| Hide user-level audit logs | Exclude user-level audit logs from collection. | False |
| Trust any certificate (not secure) | | False |
| Use system proxy settings | | False |

## Data collected

Events land in the **`cloudflare_account_audit_raw`** dataset (`vendor = cloudflare`, `product = account_audit`).
Each event carries the original Cloudflare audit log fields plus:

- `_time`: set from the audit log `when` timestamp.
- `source_log_type`: `audit`.
- `cloudflare_account_id`: the account the event was collected from.

## Collection window

The integration keeps a per-account high-water mark (the newest audit `when` timestamp seen)
in its `lastRun` state, together with the IDs of the events at that boundary second. Each fetch
resumes from that mark and deduplicates the boundary, so the window advances by observed data
rather than by a fixed poll-interval offset, so a delayed or overlapping poll never leaves a gap
or re-ingests an event. Set the collection frequency with the instance's events fetch interval.

## Commands

You can execute this command from the CLI, as part of an automation, or in a playbook.

### cloudflare-audit-logs-get-events

***
Manual command to retrieve and preview Cloudflare audit log events. Used for testing and development.

#### Base Command

`cloudflare-audit-logs-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | Comma-separated Cloudflare account IDs. Defaults to the instance-configured IDs. | Optional |
| since | The time range to fetch events from (e.g. `3 days`). | Optional |
| limit | Maximum number of events to return per account. | Optional |
| should_push_events | If `true`, also push the events to the dataset. Default is `false`. | Optional |

#### Context Output

There is no context output for this command. Events are rendered to the War Room and,
when `should_push_events=true`, sent to the `cloudflare_account_audit_raw` dataset.
