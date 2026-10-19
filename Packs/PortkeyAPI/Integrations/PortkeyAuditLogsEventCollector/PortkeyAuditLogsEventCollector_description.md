## Portkey Audit Logs Event Collector

Collects control-plane audit logs from the Portkey Admin API (`GET /audit-logs`) and ingests
them into the `portkey_audit_raw` dataset.

### Prerequisites

- A Portkey **organisation-scoped admin API key** that includes the `audit_logs.list` scope.
  Provide it in the **API Key** field; it is sent as the `x-portkey-api-key` header.
- Audit logs are a Portkey **Enterprise** feature. On free and Production plans the
  control-plane audit-logs endpoint is not available.

The organisation is implied by the API key, so no organisation ID is configured. Each audit
record carries its own `organisation_id`, which the collector stamps onto the event.

### Collection behaviour

- The collector advances a high-water mark (the newest audit `timestamp` seen), so a delayed
  or overlapping poll never leaves a gap and never duplicates.
- Each event is stamped with `_time` (the record `timestamp`), `source_log_type` (`audit`) and
  `portkey_organisation_id`.
