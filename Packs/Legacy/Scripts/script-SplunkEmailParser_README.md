Classifies an incident created from an email originating from Splunk. The mail type should be in plain text, and inline. The table should be selected.
Parsing should be done in the following manner. The "type" is the header sourcetype, the "severity" is the mail importance level, the "incident name" is the mail subject and the systems are taken from the host.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | splunk, ingestion |


## Dependencies
---
This script uses the following commands and scripts.
* search

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| body | The content's (body) of the email. |
| subject | The subject of the email. |

## Outputs
---
There are no outputs for this script.
