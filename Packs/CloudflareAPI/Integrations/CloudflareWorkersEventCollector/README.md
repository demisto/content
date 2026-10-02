# Cloudflare Workers Event Collector

Collects the Cloudflare Workers script inventory into the `cloudflare_workers_raw` dataset in the
Cortex Platform.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The Cloudflare API base URL (default `https://api.cloudflare.com/client/v4`). |
| API Token | A Cloudflare API Token with **Workers Scripts Read**, sent as a Bearer token. |
| Account IDs | Comma-separated Cloudflare account IDs to collect from. |
| Maximum number of events per fetch | Ceiling per account per run (default `5000`). |
| Events Fetch Interval | How often the collector runs (default 60 minutes). |

## Dataset

`cloudflare_workers_raw`. One event per Worker script per snapshot.

| Field | Meaning |
| --- | --- |
| `id`, `tag`, `etag` | Script identity and content hash. |
| `created_on`, `modified_on` | When the script appeared and was last changed. |
| `binding_count`, `binding_types`, `binding_names` | What the script can reach. Values are not collected. |
| `has_secret_binding` and the other `has_*_binding` flags | Whether the script holds a secret, KV, R2, D1, queue, service, Durable Object or AI binding. |
| `hostnames`, `hostname_count`, `zone_names` | The hostnames this script answers on. |
| `observability_enabled`, `logpush` | Whether the script's own logging is on. |
| `handlers`, `handler_count` | The event handlers the script exports. |
| `tail_consumer_count`, `placement_mode` | Log tailing and placement configuration. |

## Commands

### cloudflare-workers-get-events

Manual command to retrieve and preview the Workers inventory.

| Argument | Description |
| --- | --- |
| `account_ids` | Comma-separated account IDs. |
| `limit` | Maximum scripts to return per account (default `50`). |
| `should_push_events` | Also push the events to the dataset (default `false`). |
