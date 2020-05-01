Parses the Nexpose report into a clear table that contains risk scores and vulnerability counts for each server, and creates a new incident for each server.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | nexpose, ingestion |


## Dependencies
---
This script uses the following commands and scripts.
* nexpose

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | The ID of the entry containing the Nexpose report. If none is provided, the script will iterate and find a relevant entry. |
| minRiskScore | The Minimal Risk Score an item in the report needs to reach in order to trigger an incident. Leave this field empty to trigger for any risk score. |
| minVulnCount | The Minimal Vulnerability Count an item in the report needs to reach in order to trigger an incident. Leave this field empty to trigger for any count. |
| defaultNexposeSeverity | The severity to be set on the triggered incidents. |

## Outputs
---
There are no outputs for this script.
