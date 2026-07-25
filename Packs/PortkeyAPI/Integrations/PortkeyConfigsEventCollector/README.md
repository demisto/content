# Portkey Configs Event Collector

Collects the Portkey gateway config inventory from the Admin API and ingests it into the
`portkey_configs_raw` dataset in Cortex XSIAM.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The Portkey API base URL (default `https://api.portkey.ai/v1`). |
| API Key | A Portkey admin API key with the `configs.list` scope, sent as the `x-portkey-api-key` header. |
| Maximum number of events per fetch | Ceiling per run (default `5000`). |

## Dataset

`portkey_configs_raw`. One event per config per snapshot, carrying the config identity, its
workspace and organisation, status, owner and last editor.

| Field | Meaning |
| --- | --- |
| `slug` | Stable config identifier used by the gateway. |
| `owner_id` / `updated_by` | Who owns the config and who last changed it. |
| `updated_by_owner` | Whether the last editor was also the owner. |
| `status` | Whether the config is active. |

## Commands

### portkey-configs-get-events

Manual command to retrieve and preview the config inventory.

| Argument | Description |
| --- | --- |
| `limit` | Maximum records to return (default `50`). |
| `should_push_events` | Also push the events to the dataset (default `false`). |
