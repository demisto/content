# CircleCI Pipelines Event Collector

Collects pipeline activity from the CircleCI v2 API and ingests it into the
`circleci_pipelines_raw` dataset in Cortex XSIAM.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The CircleCI API v2 base URL (default `https://circleci.com/api/v2`). |
| API Token | A CircleCI personal API token, sent as the `Circle-Token` header. |
| Organisation slugs | Comma-separated organisation slugs (e.g. `gh/MyOrg`, `circleci/<org-id>`). |
| First fetch time | Time range fetched on the first run (default `3 days`). |
| Maximum number of pipelines per organisation per fetch | Ceiling per organisation per run (default `5000`). |
| Events Fetch Interval | How often the collector runs (default 5 minutes). |

## Commands

### circleci-pipelines-get-events

Retrieves pipeline events for testing and development.

| Argument | Description |
| --- | --- |
| org_slugs | Comma-separated organisation slugs. Defaults to the instance configuration. |
| since | Time range to fetch (e.g. `3 days`). |
| limit | Maximum events per organisation (default 50). |
| should_push_events | Also push the fetched events to the dataset (default `false`). |

## Collection behaviour

Pipelines are returned newest-first; the collector advances a per-organisation high-water
mark (the newest `created_at` seen) with boundary-id dedup, so overlapping polls neither
gap nor duplicate. Each event carries `_time`, `source_log_type` and `circleci_org_slug`.
