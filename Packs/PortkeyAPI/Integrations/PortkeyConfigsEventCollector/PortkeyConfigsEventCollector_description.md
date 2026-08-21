## Portkey Configs Event Collector

Collects the gateway config inventory from the Portkey Admin API (`GET /configs`) and ingests
it into the `portkey_configs_raw` dataset.

### Prerequisites

- A Portkey admin API key with the `configs.list` scope. Provide it in the **API Key** field;
  it is sent as the `x-portkey-api-key` header.

### What a config is

A Portkey config defines how requests are routed: the provider and model selected, the
fallback and retry behaviour, caching, and which guardrails are attached. A change to a config
is therefore a governance change, which is what makes the inventory worth collecting.

### Collection behaviour

- Configs are current configuration, so each run sends the full snapshot. Comparing snapshots
  over time detects a config that was newly created, re-owned or retired.
- `updated_by_owner` records whether the last editor was also the config owner, so a
  correlation can surface a config changed by someone other than its owner.
- Each record is stamped with `_time`, `snapshot_at` and `source_log_type` (`config`).

### Endpoint limitations

- `GET /configs` takes no parameters and is not paginated. It returns the identical full list
  whatever page is requested, so the collector issues a single request per run.
- The list returns config metadata only. The config body, holding the routing rules and the
  attached guardrails, is served by `GET /configs/{slug}` and needs the separate `configs.read`
  scope.
