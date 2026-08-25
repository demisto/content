# Portkey LLM Request Logs Event Collector

Collects Portkey gateway request logs into the `portkey_llm_requests_raw` dataset in the
Cortex Platform.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The Portkey API base URL (default `https://api.portkey.ai/v1`). |
| API Key | A Portkey admin API key with `logs.list`, `logs.view` and `logs.export`. |
| Workspace slugs | Comma-separated workspace slugs, for example `ws-example-a1b2c3`. Not the workspace UUID. |
| First fetch time | How far back to collect on the first run (default `1 day`). |
| Collection lag (minutes) | How far behind the present each window stops (default `5`). |
| Include prompt and response bodies | Collect full prompt and completion text (default `true`). |
| Events Fetch Interval | How often the collector runs (default 5 minutes). |

## Dataset

`portkey_llm_requests_raw`. One event per gateway request.

| Field | Meaning |
| --- | --- |
| `ai_model` / `ai_org` | The model called and the provider it was routed to. |
| `request` / `response` | The prompt and completion, when body collection is enabled. |
| `request_details` | The upstream URL and headers, which identify the egress destination. |
| `req_units` / `res_units` / `total_units` | Token usage. |
| `cost`, `response_time`, `response_status_code`, `is_success` | Spend, latency and outcome. |
| `trace_id`, `metadata` | Correlation identifiers and caller-supplied metadata. |
| `generated_at` | The request time, normalised to ISO 8601 and used for `_time`. |
| `portkey_workspace_slug` | The workspace the record was collected from. |

## Commands

### portkey-log-exports-get-events

Reports how many request logs are available for a window without running an export. Useful
for sizing ingestion before enabling collection.

| Argument | Description |
| --- | --- |
| `since` | How far back to count (default `1 day`). |

### portkey-log-exports-cancel-export

Cancels a running log export by id.

An export is collected in stages across fetches, so one that never reaches a finished state
holds its workspace: no new window is measured while it is outstanding. Cancelling releases
it. The cancelled state is terminal, so the next fetch drops the job and re-measures the same
window, and because the watermark does not move, cancelling skips no records.

Cancel is rejected by the API for an export that was never started. That is reported plainly
rather than as an error, because a draft that never ran needs no cancelling.

| Argument | Description |
| --- | --- |
| `export_id` | The id of the log export to cancel. Required. |
