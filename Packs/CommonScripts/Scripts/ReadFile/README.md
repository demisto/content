Load the contents of a file into context.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Tags | Utility, ingestion |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Integration Troubleshooting
* Rapid IOC Hunting Playbook

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | War room entryID of the file to read. |
| maxFileSize | Maximal file size to load, in bytes. Default is 1MB. |
| input_encoding | The character encoding of the file |
| output_data_type | The data type to which the output data is converted. |
| output_meta_data | Set to true to output the meta data with the payload to `ReadFile` in the context, otherwise only the payload will be output to `FileData` in the context |

## Outputs  
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| FileData | Data read from war room file | Unknown |
| ReadFile.Data | Data read from war room file | Unknown |
| ReadFile.EntryID | File Entry ID | string |
| ReadFile.FileSize | File Size | number |
| ReadFile.EOF | Whether the file has reached end-of-file. | boolean |
