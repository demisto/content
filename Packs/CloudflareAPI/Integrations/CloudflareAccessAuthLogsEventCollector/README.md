# Cloudflare Access Authentication Logs Event Collector

Collects Zero Trust Access authentication logs from the Cloudflare API and ingests them into the
`cloudflare_access_auth_raw` dataset in Cortex XSIAM.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The Cloudflare API base URL (default `https://api.cloudflare.com/client/v4`). |
| API Token | A Cloudflare API Token with the Access: Audit Logs Read permission (Account Settings Read as a fallback). |
| Account IDs | Comma-separated Cloudflare account IDs to collect from. |
| First fetch time | Time range fetched on the first run (default `3 days`). |
| Maximum number of events per account per fetch | Ceiling per account per run (default `5000`). |

## Commands

### cloudflare-access-auth-logs-get-events

Retrieves Access authentication log events for testing and development.

| Argument | Description |
| --- | --- |
| account_ids | Comma-separated Cloudflare account IDs. Defaults to the instance configuration. |
| since | Time range to fetch (e.g. `3 days`). |
| limit | Maximum events per account (default 50). |
| should_push_events | Also push the fetched events to the dataset (default `false`). |

## Collection behaviour

Records are collected ascending across the time window, advancing a per-account high-water mark
(newest `created_at`) with `ray_id` boundary dedup, so overlapping polls neither gap nor
duplicate. Each event carries `_time`, `source_log_type` and `cloudflare_account_id`. Data is
produced only for accounts that use Cloudflare Zero Trust Access.
