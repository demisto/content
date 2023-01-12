To parse the context data after running  xsoar-ws-get-action-status and resend emails to recipients who have not responded

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* xsoar-data-collection-response-tracking

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| uuid | xsoar-ws job UUID |
| emailsubject | subject of the email |
| attachIDs | files to attach to the email |

## Outputs
---
There are no outputs for this script.
