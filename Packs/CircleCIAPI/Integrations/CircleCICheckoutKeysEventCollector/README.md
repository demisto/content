# CircleCI Checkout Keys Event Collector

Collects the project checkout-key (deploy/SSH key) inventory from the CircleCI v2 API and
ingests it into the `circleci_checkout_keys_raw` dataset in Cortex XSIAM. Only public key
material is returned by the API.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The CircleCI API v2 base URL (default `https://circleci.com/api/v2`). |
| API Token | A CircleCI personal API token, sent as the `Circle-Token` header. |
| Organisation slugs | Comma-separated organisation slugs for automatic project discovery. |
| Project slugs | Comma-separated project slugs collected in addition to auto-discovered projects. |
| Maximum number of keys per fetch | Ceiling per project per run (default `5000`). |
| Events Fetch Interval | How often the collector runs (default 60 minutes). |

At least one of Organisation slugs or Project slugs is required.

## Commands

### circleci-checkout-keys-get-events

Retrieves the checkout-key inventory for testing and development.

| Argument | Description |
| --- | --- |
| project_slugs | Comma-separated project slugs. Defaults to the instance configuration. |
| org_slugs | Comma-separated organisation slugs for discovery. Defaults to the instance configuration. |
| limit | Maximum keys per project (default 50). |
| should_push_events | Also push the fetched keys to the dataset (default `false`). |

## Collection behaviour

Each run sends a full snapshot per project, stamped with `_time`/`snapshot_at`,
`source_log_type` and `circleci_project_slug`. Hyphenated API keys are normalised to
underscores. Comparing snapshots over time reveals newly added deploy or SSH keys.
