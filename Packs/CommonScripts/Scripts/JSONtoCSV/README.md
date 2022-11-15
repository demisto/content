Convert a JSON War Room output via EntryID to a CSV file.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryid | Entry id of json |
| delimiter | CSV Delimiter. |
| filename | If provided will output CSV to file. Default output is to War Room. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Name | Filename \(only in case of report type=json\) | Unknown |
| File.Type | File type e.g. "PE" \(only in case of report type=json\) | Unknown |
| File.Size | File size \(only in case of report type=json\) | Unknown |
| File.MD5 | MD5 hash of the file \(only in case of report type=json\) | Unknown |
| File.SHA1 | SHA1 hash of the file \(only in case of report type=json\) | Unknown |
| File.SHA256 | SHA256 hash of the file \(only in case of report type=json\) | Unknown |
