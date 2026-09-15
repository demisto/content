Searches Cortex XSOAR's own Threat Intel Management for File/File MD5/File SHA-256 indicators, extracts valid MD5/SHA256 values (from the indicator's value or its md5/sha256 CustomFields), and returns both the newly found hashes and the full merged set - since Netskope's v1 file hash list API has no read-back endpoint and every update replaces the full list.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Netskope |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| tags | The optional comma-separated indicator tags to further restrict the search (e.g. "malware"). If omitted, all File-type indicators are considered. |
| existing_hashes | The comma-separated list of hashes already tracked for this Netskope file hash list (from the NetskopeGetXsoarListContent script's output) - used to compute what's genuinely new and to build the full merged replace-set. |
| max_indicators | The maximum number of File indicators to pull from Cortex XSOAR per run. Default is "500". |

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
