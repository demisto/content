Displays the contents of a Cuckoo report file from a War Room entry.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | cuckoo |


## Dependencies
---
This script uses the following commands and scripts.
* ck-report

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| reportentryid | The ID of the War Room entry containing the report file. |
| sections | The sections to show (comma-separated). Can be, "info", "statistics", "network", "dropped", "suricata", "debug", "procmemory", "signatures", "decompression", "malfamily", "behavior", "target", "malscore", "static", "feeds", "strings", or "virustotal". |
| reportfilepath | The local file path to the report file. |
| reportdata | The report to be parsed.  |

## Outputs
---
There are no outputs for this script.
