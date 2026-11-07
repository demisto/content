# Portkey Workspaces Event Collector

Collects the Portkey workspace security posture from the Admin API and ingests it into the
`portkey_workspaces_raw` dataset in Cortex XSIAM.

## Configuration

| Parameter | Description |
| --- | --- |
| Server URL | The Portkey API base URL (default `https://api.portkey.ai/v1`). |
| API Key | A Portkey admin API key with the `workspaces.list` and `workspaces.read` scopes, sent as the `x-portkey-api-key` header. |
| Maximum number of events per fetch | Ceiling per run (default `5000`). |
| Events Fetch Interval | How often the collector runs (default 60 minutes). Workspace permissions change rarely. |

## Dataset

`portkey_workspaces_raw`. One event per workspace per snapshot, with the `security_settings`
permission model flattened to top-level boolean columns.

| Field | Meaning |
| --- | --- |
| `membersWriteApiKeys` | Ordinary members may create API keys. |
| `membersWriteGuardrails` | Ordinary members may change guardrails. |
| `membersViewAllData` | Ordinary members may view all workspace data. |
| `member_write_permission_count` | How many write permissions are granted to members. |
| `has_usage_limits` / `has_rate_limits` | Whether workspace-level limits are configured. |

The full permission model is collected, covering the view and write permissions for members,
managers and organisation administrators across API keys, configs, guardrails, prompts, logs
and workspace membership.

## Commands

### portkey-workspaces-get-events

Manual command to retrieve and preview the workspace posture.

| Argument | Description |
| --- | --- |
| `limit` | Maximum records to return (default `50`). |
| `should_push_events` | Also push the events to the dataset (default `false`). |
