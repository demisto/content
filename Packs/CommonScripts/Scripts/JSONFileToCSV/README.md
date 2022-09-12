Script to convert a War Room output JSON File to a CSV file.

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
| entryid | Entry ID of json |
| filename | Output CSV filename |
| delimiter | CSV delimiter. |

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
