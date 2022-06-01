Search entries in the war room for the pattern text, and mark them as evidence.

---
## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Utility |


---
## Inputs

| **Argument Name** | **Description** |
| --- | --- |
| incident_id | The incident ID to search entries from. If not given, the current incident is used. |
| tags | The list of tags to set |
| description | Evidence description |
| filter_categories | The list of categories of source entries |
| filter_options | The options to filter entries |
| filter_tags | The tags to filter entries |
| filter_entry_types | The list of entry type of source entries |
| filter_entry_formats | The list of entry format of source entries |
| algorithm | The pattern matching algorithm |
| pattern | The pattern text to search |
| exclude_pattern | The pattern text to exclude entries matched |
| node_paths | The list of node path of entries to search from |
| case_insensitive | true if the pattern is matched in case-insensitive, false otherwise. |
| dry_run | true if it only search the entries and doesn't update, false otherwise. |
| summary | The flag to control the output of results |

--
## Outputs

There are no outputs for this script.


