# Portkey API Keys Event Collector

Collects the Portkey API key inventory from the Admin API and ingests it into the
`portkey_api_keys_raw` dataset in Cortex XSIAM.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The Portkey API base URL (default `https://api.portkey.ai/v1`). |
| API Key | A Portkey admin API key with the API key list scopes, sent as the `x-portkey-api-key` header. |
| Maximum number of events per fetch | Ceiling per run (default `5000`). |

## Dataset

`portkey_api_keys_raw`. One event per API key per snapshot.

Alongside the fields returned by Portkey, each event carries flattened scalars so
correlations do not need to parse JSON:

| Field | Meaning |
| --- | --- |
| `scope_count` | Number of scopes granted to the key. |
| `rate_limit_count` | Number of rate limits configured on the key. |
| `has_usage_limit` | Whether a usage limit is configured. |
| `has_expiry` | Whether an expiry date is set. |

## Commands

### portkey-api-keys-get-events

Manual command to retrieve and preview the API key inventory.

| Argument | Description |
| --- | --- |
| `limit` | Maximum records to return (default `50`). |
| `should_push_events` | Also push the events to the dataset (default `false`). |
