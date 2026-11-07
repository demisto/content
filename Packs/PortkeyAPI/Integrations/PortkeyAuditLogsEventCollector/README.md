# Portkey Audit Logs Event Collector

Collects control-plane audit logs from the Portkey Admin API and ingests them into the
`portkey_audit_raw` dataset in Cortex XSIAM.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The Portkey API base URL (default `https://api.portkey.ai/v1`). |
| API Key | An organisation-scoped Portkey admin API key with the `audit_logs.list` scope, sent as the `x-portkey-api-key` header. |
| First fetch time | Time range fetched on the first run (default `3 days`). |
| Maximum number of events per fetch | Ceiling per run (default `5000`). |
| Page size | Records requested per page (default `100`). |
| Events Fetch Interval | How often the collector runs (default 5 minutes). Audit logs are the near real time source. |

## Commands

### portkey-audit-logs-get-events

Retrieves audit log events for testing and development.

| Argument | Description |
| --- | --- |
| since | Time range to fetch (e.g. `3 days`). |
| limit | Maximum events to return (default 50). |
| should_push_events | Also push the fetched events to the dataset (default `false`). |

## Collection behaviour

Audit records are collected across pages for the time window, then de-duplicated against a
high-water mark (newest `timestamp` plus the `request_id` values at that timestamp), so
overlapping polls neither gap nor duplicate. Each event carries `_time`, `source_log_type` and
`portkey_organisation_id`.
