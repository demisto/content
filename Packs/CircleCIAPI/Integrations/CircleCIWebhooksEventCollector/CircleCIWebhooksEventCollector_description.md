## CircleCI Webhooks Event Collector

Collects the outbound webhook inventory from the CircleCI v2 API (`GET /webhook`) and ingests
it into the `circleci_webhooks_raw` dataset.

### Prerequisites

- A **CircleCI personal API token** (create one under User Settings > Personal API Tokens).
  Provide it in the **API Token** field; it is sent as the `Circle-Token` header.
- **Organisation slug(s)** for automatic project discovery (e.g. `gh/MyOrg` or
  `circleci/<org-id>`; list yours via `GET /me/collaborations`), and/or explicit
  **project IDs** (UUIDs, as returned by `GET /project/{project-slug}`).

### Project auto-discovery

When organisation slugs are configured, the collector discovers projects from recent
pipeline activity and resolves each to its project ID automatically, with no manual ID
tracking. Discovery only sees projects with pipeline activity, so add dormant projects
explicitly via Project IDs if needed. Both settings can be combined.

### Collection behaviour

- Webhooks are current configuration (an inventory), so each run sends the full snapshot for
  every configured project. Snapshots can then be compared over time to detect newly created
  or modified webhooks.
- Each record is stamped with `_time`/`snapshot_at` (collection time), `source_log_type`
  (`webhook`) and `circleci_project_id`.
