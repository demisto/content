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
| encoding | The character encoding of the file |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| FileData | Data read from war room file | Unknown |
