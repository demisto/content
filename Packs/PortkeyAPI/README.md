# Portkey API

Integrates the Portkey API with the Cortex Platform, collecting Portkey control-plane
activity into Cortex Platform datasets and mapping it to the XDM data model.

## What this pack ships

| Content | Purpose |
| --- | --- |
| Portkey Audit Logs Event Collector | Admin API audit logs from `GET /audit-logs` into `portkey_audit_raw`, high-water-mark collection. |
| Portkey API Keys Event Collector | API key inventory from `GET /api-keys` into `portkey_api_keys_raw`, full snapshot per run. |
| Portkey Workspaces Event Collector | Workspace security posture from `GET /admin/workspaces` into `portkey_workspaces_raw`, full snapshot per run. |
| Portkey Configs Event Collector | Gateway config inventory from `GET /configs` into `portkey_configs_raw`, full snapshot per run. |
| Portkey LLM Request Logs Event Collector | Gateway request logs, including prompt, completion, model, tokens and cost, into `portkey_llm_requests_raw` via the asynchronous log export. |
| Portkey API Modeling Rule | Maps the collected datasets to the Cortex XDM data model. |
| Correlation rules | Seven detections covering API key hygiene, workspace permission posture, config ownership and new key creation. |

The pack follows a per-endpoint collector design: each Portkey API endpoint family gets its own
thin event collector and its own dataset, so log types can be modelled, retained, and correlated
independently.

The audit collector answers what changed and when. The inventory collectors answer what the
current configuration actually permits, which is what turns an audit alert into an assessable
one: a key created is routine, a key created with no expiry and the ability to create further
keys is not.

## Getting started

1. Create an **organisation-scoped Portkey admin API key**. Audit logs are a Portkey Enterprise
   feature. Grant the scopes for the collectors you intend to run:
   - Audit logs: `audit_logs.list`
   - API keys: `organisation_service_api_keys.list`, `workspace_service_api_keys.list`,
     `workspace_user_api_keys.list`
   - Workspaces: `workspaces.list`, `workspaces.read`
   - Configs: `configs.list`
   - LLM request logs: `logs.list`, `logs.view`, `logs.export`
2. Configure an instance of each collector with the key. The organisation is implied by the key,
   so no organisation ID is required.
3. Events land in the datasets below.

## Datasets

- `portkey_audit_raw`: one event per audit-log record, `_time` from the record `timestamp`.
- `portkey_api_keys_raw`: one event per API key per snapshot, with `scope_count`,
  `rate_limit_count`, `has_usage_limit` and `has_expiry` flattened for querying.
- `portkey_workspaces_raw`: one event per workspace per snapshot, with the `security_settings`
  permission model flattened to top-level boolean columns.
- `portkey_configs_raw`: one event per gateway config per snapshot, with its owner, last editor
  and status.
- `portkey_llm_requests_raw`: one event per gateway request, with the model and provider, the
  prompt and completion, token usage, cost, latency and upstream status.

## Detection content

| Rule | What it catches |
| --- | --- |
| API Key Without Expiry | A credential that stays valid until somebody revokes it by hand. |
| API Key Able to Manage API Keys | A key that can mint or delete further keys. |
| API Key Without Spend or Rate Limit | Uncapped model spend and request volume. |
| Workspace Lets Members Create API Keys | Ordinary members can issue gateway credentials. |
| Workspace Guardrails Writable By Members | Members can weaken the prompt and response controls. |
| Gateway Config Changed By Non Owner | Routing or guardrail changes made by an unexpected editor. |
| New API Key Created | A key issued outside the normal process, with actor and source address. |

The posture rules read snapshot datasets, which re-send the full inventory on every poll, so each
rule takes only the newest snapshot per object. A finding therefore raises one alert rather than
one per collection cycle.

## About GoCortex

Independent tools, projects, and ideas to complement and extend the Palo Alto Networks Cortex
ecosystem.

[gocortex.io](https://gocortex.io)
