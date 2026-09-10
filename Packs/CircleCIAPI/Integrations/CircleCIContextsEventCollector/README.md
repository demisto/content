# CircleCI Contexts Event Collector

Collects the shared-context and context environment-variable name inventory from the CircleCI
v2 API and ingests it into the `circleci_context_envvars_raw` dataset in Cortex XSIAM.
Environment-variable values are masked by the API; only names are collected.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The CircleCI API v2 base URL (default `https://circleci.com/api/v2`). |
| API Token | A CircleCI personal API token, sent as the `Circle-Token` header. |
| Organisation slugs | Comma-separated organisation slugs that own the contexts. |
| Maximum number of records per fetch | Ceiling per organisation per run (default `5000`). |
| Events Fetch Interval | How often the collector runs (default 60 minutes). |

## Commands

### circleci-contexts-get-events

Retrieves the context and environment-variable inventory for testing and development.

| Argument | Description |
| --- | --- |
| org_slugs | Comma-separated organisation slugs. Defaults to the instance configuration. |
| limit | Maximum records per organisation (default 50). |
| should_push_events | Also push the fetched records to the dataset (default `false`). |

## Collection behaviour

Each run sends a full snapshot: one record per context (`source_log_type` = `context`) and one
per environment variable name (`source_log_type` = `context_envvar`). Records are stamped with
`_time`/`snapshot_at`, `circleci_org_slug`, and (for env vars) `context_name`. Comparing
snapshots over time reveals newly created contexts and newly added secret names, which is the
data class exfiltrated in the January 2023 CircleCI incident, without ever handling the value.
