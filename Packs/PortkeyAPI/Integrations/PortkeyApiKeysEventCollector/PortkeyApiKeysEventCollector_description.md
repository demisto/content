## Portkey API Keys Event Collector

Collects the API key inventory from the Portkey Admin API (`GET /api-keys`) and ingests it
into the `portkey_api_keys_raw` dataset.

### Prerequisites

- A Portkey admin API key with the API key list scopes: `organisation_service_api_keys.list`,
  `workspace_service_api_keys.list` and `workspace_user_api_keys.list`. Provide it in the
  **API Key** field; it is sent as the `x-portkey-api-key` header.

### Collection behaviour

- API keys are current configuration, so each run sends the full snapshot. Comparing
  snapshots over time is what lets a correlation detect a key that was newly created, whose
  scopes were widened, or whose expiry was removed.
- The `scopes` array is preserved as collected, so a correlation can test for a specific
  permission such as the ability to create further API keys.
- The values correlations filter on are flattened to top-level columns so no JSON parsing is
  needed at query time: `scope_count`, `rate_limit_count`, `has_usage_limit` and `has_expiry`.
- Each record is stamped with `_time`, `snapshot_at` and `source_log_type` (`api_key`).
