## Portkey Workspaces Event Collector

Collects the workspace security posture from the Portkey Admin API
(`GET /admin/workspaces`) and ingests it into the `portkey_workspaces_raw` dataset.

### Prerequisites

- A Portkey admin API key with the `workspaces.list` and `workspaces.read` scopes. Provide it
  in the **API Key** field; it is sent as the `x-portkey-api-key` header.

Note that the organisation-scoped path is `/admin/workspaces`. The bare `/workspaces` path is
rejected for an organisation service key even when the workspace scopes are granted.

### Collection behaviour

- Workspace settings are current configuration, so each run sends the full posture snapshot
  for every workspace.
- The `security_settings` object defines the workspace permission model: which role may view
  or write API keys, configs, guardrails, prompts, logs and workspace membership. Those
  booleans are flattened to top-level columns so a posture correlation can filter on a single
  dangerous setting.
- The member write permissions are the most security-relevant. `membersWriteApiKeys` lets an
  ordinary workspace member mint API keys, and `membersWriteGuardrails` lets one weaken the
  safety controls. `member_write_permission_count` summarises how many write permissions are
  granted to members.
- Each record is stamped with `_time`, `snapshot_at` and `source_log_type`
  (`workspace_posture`).
