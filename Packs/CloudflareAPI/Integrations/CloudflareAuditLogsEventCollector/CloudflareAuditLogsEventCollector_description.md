## Cloudflare Audit Logs Event Collector

This integration collects account **audit logs** from Cloudflare and ingests them into
Cortex XSIAM (dataset: `cloudflare_account_audit_raw`).

### Prerequisites

1. Create a Cloudflare **API Token** (My Profile > API Tokens > Create Token).
2. Grant the token the **Account Settings > Read** permission. In the token editor
   (My Profile > API Tokens > your token > Edit), under **Permissions** set the three
   dropdowns to:
   - 1st: **Account**
   - 2nd: **Account Settings**
   - 3rd: **Read**
3. Scope the token to the account(s) you want to collect from (Account Resources > your account).
4. Copy your Cloudflare **Account ID** (Account Home > the ID shown in the URL/overview).

> **Important: pick the right permission.** The account audit log requires **Account Settings:
> Read**. The similarly named **"Access: Audit Logs Read"** permission is for Cloudflare Access
> (Zero Trust) authentication logs, **not** the account audit trail. A token with only that
> permission returns `403 Authentication error (code 10000)` from `/accounts/{id}/audit_logs`.

### Configuration

- **Server URL**: leave as the default `https://api.cloudflare.com/client/v4` unless using a proxy gateway.
- **API Token**: paste the token created above into the password field.
- **Account IDs**: one or more account IDs, comma-separated.
- **First fetch time**: how far back to pull on the first run (default `3 days`).

The token value is stored encrypted by the platform and is never written to logs.
