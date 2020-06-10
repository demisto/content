Converts a JSON War Room output via EntryID into a CSV file.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | - |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryid | The entry ID of the JSON. |
| delimiter | The CSV delimiter. |
| filename | The filename, if provided, will output the CSV to file. The default output is to the War Room. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Name | The filename. (only in case of report type=json) | Unknown |
| File.Type | The file type. For example, "PE". (only in case of report type=json) | Unknown |
| File.Size | The file size. (only in case of report type=json) | Unknown |
| File.MD5 | The MD5 hash of the file. (only in case of report type=json) | Unknown |
| File.SHA1 | The SHA1 hash of the file. (only in case of report type=json) | Unknown |
| File.SHA256 | The SHA256 hash of the file. (only in case of report type=json) | Unknown |
