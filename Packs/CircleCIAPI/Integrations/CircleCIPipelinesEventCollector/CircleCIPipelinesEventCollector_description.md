## CircleCI Pipelines Event Collector

Collects pipeline activity from the CircleCI v2 API (`GET /pipeline`) and ingests it into the
`circleci_pipelines_raw` dataset.

### Prerequisites

- A **CircleCI personal API token** (create one under User Settings > Personal API Tokens).
  Provide it in the **API Token** field; it is sent as the `Circle-Token` header.
- One or more **organisation slugs** (e.g. `gh/MyOrg` or `circleci/<org-id>`). You can list
  the organisations your token can see via `GET /me/collaborations`.

### Collection behaviour

- Pipelines are fetched newest-first and the collector advances a per-organisation
  high-water mark, so delayed or overlapping polls never leave a gap and never duplicate.
- Each event is stamped with `_time` (pipeline `created_at`), `source_log_type` (`pipeline`)
  and `circleci_org_slug`.
