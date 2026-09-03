Resolves a private app (ZTNA/NPA) ID from a name. ***netskopev2-list-private-apps*** has no name filter argument, so this fetches every private app and matches by name in Python - also handling the brackets Netskope wraps `app_name` in on list responses (e.g. `"[test server]"`).

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Netskope |

## Dependencies

---
This script uses the following commands and scripts.

* netskopev2-list-private-apps

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| app_id | App ID, if already known. If provided, used directly - no lookup happens. |
| app_name | App name to look up if app_id isn't provided. Matched case-insensitively against netskopev2-list-private-apps' app_name field. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ResolvedAppId.app_id | The resolved (or directly provided) app ID. Empty if resolution failed. | String |
| ResolvedAppId.resolved_by | Whether the ID came from app_id directly, an app_name lookup, or neither was provided. | String |
| ResolvedAppId.error | Error message if resolution failed (no match, or ambiguous multiple matches). Empty on success. | String |
