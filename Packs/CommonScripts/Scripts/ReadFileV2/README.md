Load the contents of a file into context.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility, ingestion |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | War room entryID of the file to read. |
| max_file_size | Maximal file size to load, in bytes. Default is 1MB. |
| input_encoding | The character encoding of the file |
| output_data_type | The data type to which the output data is converted |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ReadFile.Data | Data read from war room file | Unknown |
| ReadFile.EntryID | File Entry ID | string |
| ReadFile.FileSize | File Size | number |
| ReadFile.EOF | Whether the file has reached end-of-file. | boolean |
