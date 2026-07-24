# CircleCI API

Integrates the CircleCI v2 API with Cortex, collecting CircleCI control-plane and pipeline
activity into Cortex datasets, mapping it to the XDM data model, and detecting CI/CD security
risks with correlation rules.

The pack follows a per-endpoint collector design: each CircleCI v2 endpoint family has its own
thin event collector and its own dataset, so log types can be modelled, retained, and correlated
independently. Detection content is grounded in the OWASP CI/CD Top 10, with a focus on Poisoned
Pipeline Execution, persistence, and secrets exposure.

## Event collectors

| Collector | Source | Dataset |
| --- | --- | --- |
| CircleCI Pipelines Event Collector | `GET /pipeline` (pipeline activity) | `circleci_pipelines_raw` |
| CircleCI Webhooks Event Collector | `GET /webhook` (outbound webhook inventory) | `circleci_webhooks_raw` |
| CircleCI Triggers Event Collector | `GET /projects/{id}/pipeline-definitions/{id}/triggers` (scheduled and push triggers) | `circleci_triggers_raw` |
| CircleCI Contexts Event Collector | `GET /context` and its environment-variable names | `circleci_context_envvars_raw` |
| CircleCI Project Settings Event Collector | `GET /project/{slug}/settings` (advanced settings posture) | `circleci_project_settings_raw` |
| CircleCI Checkout Keys Event Collector (Under Development) | `GET /project/{slug}/checkout-key` (deploy/SSH key inventory) | `circleci_checkout_keys_raw` |

Pipelines use rolling high-water-mark collection. The other collectors take periodic inventory
snapshots so that snapshot-over-snapshot comparison can detect a newly created object. The
Checkout Keys collector is under development and disabled by default: the v2 API exposes only
deploy/checkout keys, not the separate Additional SSH Keys surface, so it can return no data for
some organisations.

## Detection content

The pack ships XDM modelling for every populated dataset and the following correlation rules:

| Correlation | Detects | MITRE |
| --- | --- | --- |
| CircleCI - New Pipeline Created | A newly created pipeline | TA0002 / T1072 |
| CircleCI - New Outbound Webhook Created | A newly created outbound webhook, a potential exfiltration channel | TA0010 / T1567 |
| CircleCI - New Pipeline Trigger Created | A newly created scheduled or push trigger, a persistence vector | TA0003 / T1053 |
| CircleCI - New Context or Context Secret | A newly created shared context or secret name, the data class exfiltrated in the January 2023 CircleCI incident | TA0006 / T1552 |
| CircleCI - Insecure Fork Build Settings | A project where forked pull requests can build or receive the project's secrets, a Poisoned Pipeline Execution precondition | TA0001 / T1195 |

## Getting started

1. Create a CircleCI **personal API token** (User Settings > Personal API Tokens).
2. Find your **organisation slug** with `GET /me/collaborations` (for example `gh/MyOrg` or
   `circleci/<org-id>`).
3. Configure an instance of each collector you want, providing the API token and the
   organisation slug. Most collectors auto-discover projects from recent pipeline activity, so
   project IDs do not need to be tracked manually; dormant projects (no pipeline activity) can be
   added explicitly.
4. Events land in the datasets listed above and are mapped to XDM automatically.

## Datasets

- `circleci_pipelines_raw`: one event per pipeline, `_time` is the pipeline creation time.
- `circleci_webhooks_raw`: full webhook inventory snapshot per fetch.
- `circleci_triggers_raw`: full trigger inventory snapshot per fetch, scheduled and push triggers.
- `circleci_context_envvars_raw`: one record per shared context and per context secret name.
  Secret values are masked by the API; only names are collected.
- `circleci_project_settings_raw`: advanced project-settings posture, one record per project.
- `circleci_checkout_keys_raw`: checkout/deploy key inventory (collector under development).

## Requirements

- A CircleCI personal API token. The audit-relevant endpoints are read-only.

## Licence

Licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
Copyright (c) GoCortexIO.
