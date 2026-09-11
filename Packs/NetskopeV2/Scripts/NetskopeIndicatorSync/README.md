Pulls Domain, URL, IP, and CIDR indicators from Cortex XSOAR's Threat Intel Management and formats CIDR values with the `CIDR:` prefix that Netskope's destination profile Definition field expects. It skips values already present in the target profile. When `profile_id` is given, it appends the new values in batches that match the API's per-call cap and deploys the result. Without `profile_id`, it only prepares the new-value list for a separate create-profile step.

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
| tags | The optional comma-separated indicator tags to further restrict the search (e.g. "netskope-block"). If omitted, all indicators of the given indicator_types are considered. |
| skip_tags | The optional comma-separated indicator tags to exclude - any indicator carrying one of these tags is skipped even if it matches tags/indicator_types. |
| indicator_types | The comma-separated indicator types to pull from Cortex XSOAR's Threat Intel. Must be one or more of Domain, URL, IP, CIDR. |
| profile_id | The ID of an existing Netskope Destination Profile to append the new values to (and deploy). If omitted, no append/deploy happens - the script only searches, formats, and returns the new values (for a separate create-profile step to consume). |
| existing_values | The comma-separated list of values already in the target destination profile (from netskopev2-list-destination-profiles) - used to skip values that are already blocked. Ignored if profile_id is omitted. |
| max_indicators | The maximum number of indicators to pull from Cortex XSOAR per run. Default is "500". |
| chunk_size | The maximum number of values per append call, matching netskopev2-update-destination-profile-values' 1-10-per-call limit. Default is "10". |
| deploy | Whether the deploy option is enabled. If profile_id is set and any new values were appended, deploy the profile afterward so the change takes effect immediately. Default is "true". |
| change_note | The optional change note recorded on the deploy call. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Netskope.Sync.ProfileId | The destination profile ID that was updated (null if this was a create-prep run). | String |
| Netskope.Sync.Query | The indicator search query that was run. | String |
| Netskope.Sync.TotalFound | The total indicators returned by the query (before dedup). | Number |
| Netskope.Sync.SkippedExisting | The number of values skipped because they were already present in the profile or duplicated within this run. | Number |
| Netskope.Sync.SkippedNoValue | The number of indicators skipped because they did not contain a value. | Number |
| Netskope.Sync.NewCount | The number of new values found. | Number |
| Netskope.Sync.AddedCount | The number of new values actually appended to profile_id (0 if profile_id was omitted). | Number |
| Netskope.Sync.Batches | The number of append batches used. | Number |
| Netskope.Sync.Deployed | The value indicating whether the profile was deployed after appending. | Boolean |
| Netskope.Sync.AllNewValues | The flat list of all new, formatted values - for creating a brand-new profile in one call when profile_id was omitted. | List |
