## Cloudflare Audit Logs V2 Event Collector

This integration collects account audit logs from Cloudflare's **version 2** audit API and ingests
them into the Cortex Platform (dataset: `cloudflare_account_audit_v2_raw`).

### Why this exists alongside the version 1 collector

Cloudflare exposes two audit APIs that return **different records**, and only version 2 reports
authentication:

| Endpoint | Sign-in events |
| --- | --- |
| `/accounts/{id}/logs/audit` (version 2, this collector) | Yes, as `LOGIN` |
| `/accounts/{id}/audit_logs` (version 1) | No |

Over an identical period, version 1 returns records and no sign-in of any kind.
An account can therefore appear fully audited while every dashboard login goes unrecorded. The two
endpoints use different record identifiers, so neither is a drop-in replacement for the other, and
running both is deliberate.

A `LOGIN` record carries the actor's email address, source IP address and the outcome, which is
what makes an authentication detection possible.

### Prerequisites

1. Create a Cloudflare **API Token** (My Profile > API Tokens > Create Token).
2. Grant the token the **Account Settings > Read** permission. In the token editor, under
   **Permissions**, set the three dropdowns to:
   - 1st: **Account**
   - 2nd: **Account Settings**
   - 3rd: **Read**
3. Scope the token to the account(s) you want to collect from (Account Resources > your account).
4. Copy your Cloudflare **Account ID** (Account Home > the ID shown in the URL or overview).

> **Important: pick the right permission.** The account audit log requires **Account Settings:
> Read**. The similarly named **"Access: Audit Logs Read"** permission is for Cloudflare Access
> (Zero Trust) authentication logs, **not** the account audit trail. So is **"Access: Users"**.
> A token holding only those returns `403 Authentication error (code 10000)`.

### Configuration

- **Server URL**: leave as the default `https://api.cloudflare.com/client/v4` unless using a proxy gateway.
- **API Token**: paste the token created above into the password field.
- **Account IDs**: one or more account IDs, comma-separated.
- **First fetch time**: how far back to pull on the first run (default `3 days`).

The token value is stored encrypted by the platform and is never written to logs.

### Notes on this endpoint

- It requires both a start and an end bound on every request.
- It ignores page numbers: requesting page 1, 2 or 3 returns the same records every time. Paging
  is by an opaque cursor, which this collector follows automatically.
- Sign-in events have been observed arriving within roughly ninety seconds. Allow for that lag
  when setting the search window on any correlation built over this dataset.
