# Portkey API

Integrates the Portkey API with Cortex, collecting Portkey control-plane activity into Cortex
datasets and mapping it to the XDM data model.

## What this pack ships

| Content | Purpose |
| --- | --- |
| Portkey Audit Logs Event Collector | Admin API audit logs from `GET /audit-logs` into `portkey_audit_raw`, high-water-mark collection. |
| Portkey API Keys Event Collector | API key inventory from `GET /api-keys` into `portkey_api_keys_raw`, full snapshot per run. |
| Portkey Workspaces Event Collector | Workspace security posture from `GET /admin/workspaces` into `portkey_workspaces_raw`, full snapshot per run. |
| Portkey Configs Event Collector | Gateway config inventory from `GET /configs` into `portkey_configs_raw`, full snapshot per run. |
| Portkey API Modeling Rule | Maps the collected datasets to the Cortex XDM data model. |

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

## About GoCortex

Independent tools, projects, and ideas to complement and extend the Palo Alto Networks Cortex
ecosystem.

[gocortex.io](https://gocortex.io)
