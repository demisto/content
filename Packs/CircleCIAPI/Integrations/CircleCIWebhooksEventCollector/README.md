# CircleCI Webhooks Event Collector

Collects the outbound webhook inventory from the CircleCI v2 API and ingests it into the
`circleci_webhooks_raw` dataset in Cortex XSIAM.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The CircleCI API v2 base URL (default `https://circleci.com/api/v2`). |
| API Token | A CircleCI personal API token, sent as the `Circle-Token` header. |
| Organisation slugs | Comma-separated organisation slugs for automatic project discovery from recent pipeline activity. |
| Project IDs | Comma-separated project IDs (UUIDs) collected in addition to auto-discovered projects. |
| Maximum number of webhooks per fetch | Ceiling per project per run (default `5000`). |
| Events Fetch Interval | How often the collector runs (default 60 minutes). |

At least one of Organisation slugs or Project IDs is required. Auto-discovery walks recent
pipeline activity, so dormant projects (no pipelines) should be listed explicitly.

## Commands

### circleci-webhooks-get-events

Retrieves the webhook inventory for testing and development.

| Argument | Description |
| --- | --- |
| project_ids | Comma-separated project IDs (UUIDs). Defaults to the instance configuration. |
| limit | Maximum webhooks per project (default 50). |
| should_push_events | Also push the fetched webhooks to the dataset (default `false`). |

## Collection behaviour

Webhooks are current configuration (an inventory): each run sends the full snapshot per
project, stamped with `_time`/`snapshot_at`, `source_log_type` and `circleci_project_id`.
Comparing snapshots over time reveals newly created or modified webhooks.
