Searches XSOAR's own Threat Intel Management for File/File MD5/File SHA-256 indicators, extracts valid MD5/SHA256 values (from the indicator's value or its md5/sha256 CustomFields), and returns both the newly found hashes and the full merged set - since Netskope's v1 file hash list API has no read-back endpoint and every update replaces the full list.

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
| tags | Optional comma-separated indicator tags to further restrict the search. If omitted, all File-type indicators are considered. |
| existing_hashes | Comma-separated list of hashes already tracked for this Netskope file hash list - used to compute what's genuinely new and to build the full merged replace-set. |
| max_indicators | Maximum number of File indicators to pull from XSOAR per run. Default is 500. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NetskopeHashSync.query | The indicator search query that was run. | String |
| NetskopeHashSync.total_found_indicators | Total File indicators returned by the query. | Number |
| NetskopeHashSync.skipped_no_valid_hash | Number of File indicators skipped because no valid MD5/SHA256 hash could be extracted from them. | Number |
| NetskopeHashSync.new_count | Number of hashes found that aren't already in existing_hashes. | Number |
| NetskopeHashSync.new_hashes | The newly found hashes not already tracked. | Unknown |
| NetskopeHashSync.merged_hashes | existing_hashes plus new_hashes, deduplicated and sorted - the full set to send as a replace to netskopev2-update-file-hash-list. | Unknown |
