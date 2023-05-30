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
| entryID | War Room entryID of the file to read. |
| maxFileSize | Maximal file size to load, in bytes. Default is 1MB. |
| input_encoding | The character encoding of the file. |
| output_data_type | The data type to which the output data is converted. |
| output_metadata | Set true in order to output additional metadata on the file, to context |

## Outputs  
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| FileData | Data read from the War Room file. | Unknown |
| ReadFile.Data | Data read from the War Room file. | Unknown |
| ReadFile.EntryID | File entry ID. | string |
| ReadFile.FileSize | File size. | number |
| ReadFile.EOF | Whether the file has reached end-of-file. | boolean |
