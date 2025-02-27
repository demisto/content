Performs a Yara scan on the specified files.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | - |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| yaraRule | The Yara rule to use for the file scan. |
| entryIDs | A comma-separated list of file entry IDs to scan. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Yara.Filename | The filename of the file that was scanned. | string |
| Yara.HasError | Whether there was an error when performing the scan. | boolean |
| Yara.HasMatch | Whether the file matched any of the rules. | boolean |
| Yara.entryID | The entry ID of the scanned file. | string |
| Yara.fileID | The file ID of the scanned file. | string |
| Yara.MatchCount | The number of rules that matched the file. | number |
| Errors | A list of errors that occurred during the scan. | Unknown |
| Matches.Meta | Metadata about the rule (as defined in the rule itself). | Unknown |
| Matches.Namespace | The namespace defined in the rule. | string |
| Matches.RuleName | The rule name that matched. | string |
| Matches.Strings | A list of strings that the rule matched. | string |
| Matches.Tags | A list of tags that are defined in the rule. | Unknown | 
