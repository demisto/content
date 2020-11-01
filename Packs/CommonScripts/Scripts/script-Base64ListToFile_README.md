Converts a Base64 file in a list to a binary file and upload it to the War Room.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | list, Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| listname | The list name of Base64 items. The list needs to be a single file in a list. |
| filename | The optional War Room output filename. The default filename is list name. |
| isZipFile | Whether the data is compressed (zip format). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Name | The filename (only in the case of a report type=json). | Unknown |
| File.Type | The file type. For example, "PE" (only in the case of a report type=json). | Unknown |
| File.Size | The file size (only in the case of a report type=json). | Unknown |
| File.MD5 | The MD5 file hash of the file (only in the case of a report type=json). | Unknown |
| File.SHA1 | The SHA1 file hash of the file (only in the case of a report type=json). | Unknown |
| File.SHA256 | The SHA256 file hash of the file (only in the case of a report type=json). | Unknown |
| File.EntryID | The EntryID of the file (only in the case of a report type=json). | Unknown |
