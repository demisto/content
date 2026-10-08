Fetches all private apps and matches one by name to resolve its application ID. This is necessary because ***netskopev2-list-private-apps*** has no name filter argument and Netskope wraps `app_name` in brackets in list responses, for example, `"[test server]"`.

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
| app_id | The app ID, if already known. If provided, used directly - no lookup happens. |
| app_name | The app name to look up if app_id isn't provided. Matched case-insensitively against netskopev2-list-private-apps' app_name field (Netskope wraps that field in brackets, e.g. "[test server]" - this handles that automatically). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Netskope.ResolvedAppId.AppId | The resolved (or directly provided) app ID. Empty if resolution failed. | String |
| Netskope.ResolvedAppId.ResolvedBy | The value indicating whether the ID came from app_id directly, an app_name lookup, or neither was provided. | String |
| Netskope.ResolvedAppId.Error | The error message if resolution failed (no match, or ambiguous multiple matches). Empty on success. | String |
