## CircleCI Project Settings Event Collector

Collects the advanced project-settings posture from the CircleCI v2 API
(`GET /project/{provider}/{organization}/{project}/settings`) and ingests it into the
`circleci_project_settings_raw` dataset.

The advanced settings include the Poisoned Pipeline Execution preconditions:
`forks_receive_secret_env_vars` (forked pull requests receive the project's secrets) and
`build_fork_prs` (forked pull requests can trigger builds), plus `disable_ssh`, `oss` and
`write_settings_requires_admin`.

### Prerequisites

- A **CircleCI personal API token** (create one under User Settings, Personal API Tokens).
  Provide it in the **API Token** field; it is sent as the `Circle-Token` header.
- **Organisation slug(s)** for automatic project discovery (e.g. `gh/MyOrg` or
  `circleci/<org-id>`), and/or explicit **project slugs** (e.g. `gh/MyOrg/my-repo`).

### Collection behaviour

- Settings are current configuration (a posture snapshot), so each run sends the full snapshot
  for every covered project. The `advanced` settings object is flattened to top-level boolean
  columns.
- Each record is stamped with `_time`/`snapshot_at`, `source_log_type` (`project_settings`) and
  `circleci_project_slug`.
