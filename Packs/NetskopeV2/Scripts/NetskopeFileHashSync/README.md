Searches Cortex XSOAR's own Threat Intel Management for the generic "File" type plus the hash-specific "File MD5"/"File SHA-256" types (some tenants disable the hash-specific types as selectable options, in which case new hash indicators land under generic "File" instead - searching both covers either case), extracts valid MD5 (32 hex chars) / SHA256 (64 hex chars) hashes from either the indicator's value or its md5/sha256 CustomFields, and - since Netskope's v1 file hash list API has no read-back endpoint and every update replaces the full list - returns both the newly found hashes and the full merged set (existing_hashes plus new) ready to send as a full replace.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| tags | The optional comma-separated indicator tags to further restrict the search \(e.g. "malware"\). If omitted, all File-type indicators are considered. |
| skip_tags | The optional comma-separated indicator tags to exclude. Any indicator carrying one of these tags is skipped. |
| indicator_query | An additional Cortex XSOAR indicator query used to bound the sync. The default selects active indicators with a Bad reputation. |
| existing_hashes | The comma-separated list of hashes already tracked for this Netskope file hash list \(from the NetskopeGetXsoarListContent script's output\) - used to compute what's genuinely new and to build the full merged replace-set. |
| max_indicators | The maximum number of File indicators to pull from Cortex XSOAR per run. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Netskope.HashSync.Query | The indicator search query that was run. | String |
| Netskope.HashSync.TotalFoundIndicators | The total File indicators returned by the query. | Number |
| Netskope.HashSync.SkippedNoValidHash | The number of File indicators skipped because no valid MD5/SHA256 hash could be extracted from them. | Number |
| Netskope.HashSync.NewCount | The number of hashes found that aren't already in existing_hashes. | Number |
| Netskope.HashSync.NewHashes | The newly found hashes not already tracked. | List |
| Netskope.HashSync.MergedHashes | The existing_hashes plus new_hashes, deduplicated and sorted - the full set to send as a replace to netskopev2-update-file-hash-list. | List |
