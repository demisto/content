## Tessian Event Collector

Use this integration to collect security events from Proofpoint Tessian into Cortex XSIAM.

### Security Events

The integration fetches security events from the Proofpoint Tessian API (`GET /api/v1/events`) using checkpoint-based pagination. Each fetch cycle can make up to 10 API calls of 100 events each, for a maximum of 1000 events per cycle.

### Event Enrichment

Each event is enriched with the following XSIAM fields:

- **_time**: Set to the `created_at` timestamp of the event.
- **_ENTRY_STATUS**: Derived from comparing `updated_at` and `created_at`:
  - `new` — if `updated_at == created_at`
  - `updated` — if `updated_at > created_at`
