# CircleCI Project Settings Event Collector

Collects the advanced project-settings posture from the CircleCI v2 API and ingests it into the
`circleci_project_settings_raw` dataset in Cortex XSIAM. The advanced settings include the
Poisoned Pipeline Execution preconditions such as `forks_receive_secret_env_vars` and
`build_fork_prs`.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The CircleCI API v2 base URL (default `https://circleci.com/api/v2`). |
| API Token | A CircleCI personal API token, sent as the `Circle-Token` header. |
| Organisation slugs | Comma-separated organisation slugs for automatic project discovery. |
| Project slugs | Comma-separated project slugs collected in addition to auto-discovered projects. |
| Maximum number of projects per fetch | Ceiling per run (default `5000`). |
| Events Fetch Interval | How often the collector runs (default 6 hours). |

At least one of Organisation slugs or Project slugs is required.

## Commands

### circleci-project-settings-get-events

Retrieves the project-settings posture for testing and development.

| Argument | Description |
| --- | --- |
| project_slugs | Comma-separated project slugs. Defaults to the instance configuration. |
| org_slugs | Comma-separated organisation slugs for discovery. Defaults to the instance configuration. |
| limit | Maximum records to return (default 50). |
| should_push_events | Also push the fetched records to the dataset (default `false`). |

## Collection behaviour

Each run sends a full posture snapshot per project with the advanced settings flattened to
top-level boolean columns, stamped with `_time`/`snapshot_at`, `source_log_type` and
`circleci_project_slug`. A correlation can then flag any project where a dangerous setting such
as `forks_receive_secret_env_vars` is enabled.
