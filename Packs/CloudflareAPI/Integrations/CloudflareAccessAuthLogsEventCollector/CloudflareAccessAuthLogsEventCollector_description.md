## Cloudflare Access Authentication Logs Event Collector

Collects Zero Trust Access authentication logs from the Cloudflare API
(`GET /accounts/{account_id}/access/logs/access_requests`) and ingests them into the
`cloudflare_access_auth_raw` dataset. Each record is one authentication event against a
Cloudflare Access protected application.

### Prerequisites

- A Cloudflare **API Token** with the **Access: Audit Logs Read** permission. Some
  configurations also require **Account Settings Read**; add it if authorisation fails.
  Provide the token in the password field; it is sent as a Bearer token.
- One or more Cloudflare **account IDs**.

### Collection behaviour

- The collector advances a per-account high-water mark (the newest `created_at` seen), so a
  delayed or overlapping poll never leaves a gap and never duplicates.
- Each event is stamped with `_time` (the record `created_at`), `source_log_type`
  (`access_auth`) and `cloudflare_account_id`.

This endpoint returns data only for accounts that use Cloudflare Zero Trust Access, where users
authenticate to protected applications.
