This script runs stringsifter ML tool for malware anlisys and ranking of words.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* RDP Bitmap Cache - Detect and Hunt

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| limit | Limit output to the top limit ranked strings |
| min_score | Limit output to strings with score &amp;gt;= min-score |
| file_name | The file name - Mandatory when entring the data as string_text |
| string_text | The text to analyze with string sifter |
| entryID | The file to process. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Stringsifter.FileName | The name of the file Stringsifter operated on. | Unknown |
| Stringsifter.Results | The results from Stringsifter | Unknown |
