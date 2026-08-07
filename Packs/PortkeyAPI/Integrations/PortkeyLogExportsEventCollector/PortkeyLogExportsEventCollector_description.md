## Portkey LLM Request Logs Event Collector

Collects Portkey gateway request logs, the record of every call made through Portkey to a
model provider, into the `portkey_llm_requests_raw` dataset. These are the logs Portkey shows
under Logs, and they carry the prompt, the completion, the model and provider, the token
counts, the cost and the upstream status.

### Prerequisites

- A Portkey admin API key with the log export scopes: `logs.list`, `logs.view` and
  `logs.export`. Provide it in the **API Key** field.
- One or more workspace **slugs**, for example `ws-example-a1b2c3`.

Use the workspace slug, not the workspace UUID. The export API accepts a UUID, returns HTTP
200, and then matches no records at all, so a misconfigured instance looks healthy while
collecting nothing.

### How collection works

Portkey has no endpoint that lists request logs. The only bulk read path is an asynchronous
export job, so the collector creates an export for a time window, starts it, polls it on
later runs, and ingests the result when it completes. Export runtime therefore affects
collection latency only.

- The window is driven by a watermark rather than the collection interval, and the watermark
  advances only once the data has been downloaded. A failed export retries the same window,
  so records are neither lost nor collected twice.
- The API window is half-open, so consecutive windows meet exactly with no gap and no overlap.
- An export is capped at 50,000 records. The record count is known when the export is created,
  before it runs, so an oversized window is measured and split rather than truncated.
- A window containing no records skips the export entirely and simply moves the watermark on.

### Data volume and sensitivity

The prompt and completion bodies dominate the record size, roughly 26 KB per record in
testing, and may contain whatever your users send to a model. Turn off **Include prompt and
response bodies** to collect only the metadata, which still supports model, usage, cost and
error detections.
