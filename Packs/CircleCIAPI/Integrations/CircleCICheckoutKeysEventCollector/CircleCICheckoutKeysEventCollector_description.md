## CircleCI Checkout Keys Event Collector

> **UNDER DEVELOPMENT.** The CircleCI v2 API exposes only deploy/checkout keys, not the
> separate Additional SSH Keys surface. GitHub App projects may not populate deploy keys
> at all, so this collector can return no data for some organisations. It is shipped but
> not enabled by default while this limitation is worked through.

Collects the project checkout-key (deploy/SSH key) inventory from the CircleCI v2 API
(`GET /project/{project-slug}/checkout-key`) and ingests it into the
`circleci_checkout_keys_raw` dataset. The API returns only public key material; no private
key is ever handled.

Checkout keys grant a pipeline access to source repositories, so a newly added key can
indicate persistence or credential access in the CI/CD environment.

### Prerequisites

- A **CircleCI personal API token** (create one under User Settings, Personal API Tokens).
  Provide it in the **API Token** field; it is sent as the `Circle-Token` header.
- **Organisation slug(s)** for automatic project discovery (e.g. `gh/MyOrg` or
  `circleci/<org-id>`), and/or explicit **project slugs** (e.g. `gh/MyOrg/my-repo`).

### Collection behaviour

- Checkout keys are current configuration (an inventory), so each run sends the full
  snapshot for every covered project.
- Hyphenated API keys are normalised to underscores (`public_key`, `created_at`).
- Each record is stamped with `_time`/`snapshot_at`, `source_log_type` (`checkout_key`) and
  `circleci_project_slug`.
