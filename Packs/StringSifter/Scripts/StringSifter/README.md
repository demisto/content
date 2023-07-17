This script runs the StringSifter ML tool for malware analysis and ranking of words. You can enter an entryID or string_text as input.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.1.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| limit | Limit output to the top limit ranked strings. |
| min_score | Limit output to strings with score &amp;gt;= min-score. |
| file_name | The file name. Mandatory when entering the data as string_text. |
| string_text | The text to analyze with StringSifter. |
| entryID | The file to process. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Stringsifter.FileName | The name of the file StringSifter operated on. | Unknown |
| Stringsifter.Results | The results from StringSifter. | Unknown |
