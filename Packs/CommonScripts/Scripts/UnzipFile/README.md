Unzip a file using fileName or entryID to specify a file. Unzipped files will be loaded to the War Room and names will be put into the context.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility, file |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
Sample usage of this script can be found in the following playbooks and scripts.
* Comprehensive PAN-OS Best Practice Assessment
* Cortex XDR - Retrieve File by sha256
* CrowdStrike Falcon - Retrieve File
* Get File Sample By Hash - Cylance Protect
* Local Analysis alert Investigation
* MDE - Retrieve File
* PS Remote Get File Sample From Path
* PS-Remote Get MFT
* PS-Remote Get Registry
* Pull Request Creation - Generic

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| fileName | The file name. |
| password | Password to protect the ZIP file. |
| nonsensitive_password | Password to protect the ZIP file, inserted as a non sensative argument. |
| entryID | The entry ID of the attached ZIPp file in the War Room. |
| lastZipFileInWarroom | Enter 'yes' \(or any other value\) if the ZIP file is last ZIP file in the War Room. |
| zipTool | Tool to extract zip |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ExtractedFiles | A list of file names that were extracted from the ZIP file. | Unknown |
