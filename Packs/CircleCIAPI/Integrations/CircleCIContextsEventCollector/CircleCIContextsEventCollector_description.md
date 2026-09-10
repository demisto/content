## CircleCI Contexts Event Collector

Collects the shared-context and context environment-variable name inventory from the CircleCI
v2 API (`GET /context` and `GET /context/{context_id}/environment-variable`) and ingests it
into the `circleci_context_envvars_raw` dataset.

Environment-variable **values are masked by the API**, so this collector handles names only.
It captures which secret names exist in which context, never the secret values.

### Prerequisites

- A **CircleCI personal API token** (create one under User Settings, Personal API Tokens).
  Provide it in the **API Token** field; it is sent as the `Circle-Token` header.
- One or more **organisation slugs** that own the contexts (e.g. `gh/MyOrg` or
  `circleci/<org-id>`; list yours via `GET /me/collaborations`).

### Collection behaviour

- Contexts are current configuration (an inventory), so each run sends the full snapshot.
- Each context produces one record (`source_log_type` = `context`) and one record per
  environment variable (`source_log_type` = `context_envvar`), so a newly created context and
  a newly added secret name are each detectable.
- Every record is stamped with `_time`/`snapshot_at` (collection time) and
  `circleci_org_slug`; env-var records also carry `context_name`.
