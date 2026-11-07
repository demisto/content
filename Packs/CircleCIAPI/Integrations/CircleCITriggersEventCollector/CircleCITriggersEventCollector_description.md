## CircleCI Triggers Event Collector

Collects the pipeline trigger inventory from the CircleCI v2 API
(`GET /projects/{project_id}/pipeline-definitions` and each definition's `/triggers`) and
ingests it into the `circleci_triggers_raw` dataset. The inventory covers scheduled
triggers (with the cron expression and attribution actor) and VCS push triggers.

This is the scheduling surface used by GitHub App organisations. The legacy
scheduled-pipelines endpoint is a separate store used by classic OAuth organisations and
is not collected by this integration.

### Prerequisites

- A **CircleCI personal API token** (create one under User Settings, Personal API Tokens).
  Provide it in the **API Token** field; it is sent as the `Circle-Token` header.
- **Organisation slug(s)** for automatic project discovery (e.g. `gh/MyOrg` or
  `circleci/<org-id>`; list yours via `GET /me/collaborations`), and/or explicit
  **project IDs** (UUIDs, as returned by `GET /project/{project-slug}`).

### Project auto-discovery

When organisation slugs are configured, the collector discovers projects from recent
pipeline activity and resolves each to its project ID automatically; resolutions are
cached between runs. Discovery only sees projects with pipeline activity, so add dormant
projects explicitly via Project IDs if needed. Both settings can be combined.

### Collection behaviour

- Triggers are current configuration (an inventory), so each run sends the full snapshot
  for every covered project. Snapshots can then be compared over time to detect newly
  created or modified triggers.
- Each record carries its pipeline definition (`pipeline_definition_id`,
  `pipeline_definition_name`) and is stamped with `_time`/`snapshot_at` (collection time),
  `source_log_type` (`trigger`) and `circleci_project_id`.
