Pulls Domain/URL/IP/CIDR indicators from XSOAR's own Threat Intel Management, formats CIDR values with the `CIDR:` prefix Netskope's destination profile Definition field expects, skips values already present in the target profile, and - when `profile_id` is given - appends the new values in batches (matching the API's per-call cap) and deploys the result. Without `profile_id`, it only prepares the new-value list for a separate create-profile step.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Netskope |

## Dependencies

---
This script uses the following commands and scripts.

* netskopev2-update-destination-profile-values
* netskopev2-deploy-destination-profiles

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| tags | Optional comma-separated indicator tags to further restrict the search. If omitted, all indicators of the given indicator_types are considered. |
| skip_tags | Optional comma-separated indicator tags to exclude. |
| indicator_types | Comma-separated indicator types to pull from XSOAR's Threat Intel. Must be one or more of Domain, URL, IP, CIDR. |
| profile_id | ID of an existing Netskope Destination Profile to append the new values to (and deploy). If omitted, the script only searches, formats, and returns the new values. |
| existing_values | Comma-separated list of values already in the target destination profile - used to skip values that are already blocked. Ignored if profile_id is omitted. |
| max_indicators | Maximum number of indicators to pull from XSOAR per run. Default is 500. |
| chunk_size | Maximum number of values per append call. Default is 10. |
| deploy | If profile_id is set and any new values were appended, deploy the profile afterward. Default is true. |
| change_note | Optional change note recorded on the deploy call. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NetskopeSync.profile_id | The destination profile ID that was updated (null if this was a create-prep run). | String |
| NetskopeSync.query | The indicator search query that was run. | String |
| NetskopeSync.total_found | Total indicators returned by the query (before dedup). | Number |
| NetskopeSync.skipped_existing | Number of values skipped because they were already present in the profile or duplicated within this run. | Number |
| NetskopeSync.new_count | Number of new values found. | Number |
| NetskopeSync.added_count | Number of new values actually appended to profile_id (0 if profile_id was omitted). | Number |
| NetskopeSync.batches | Number of append batches used. | Number |
| NetskopeSync.deployed | Whether the profile was deployed after appending. | Boolean |
| NetskopeSync.all_new_values | Flat list of all new, formatted values. | Unknown |
