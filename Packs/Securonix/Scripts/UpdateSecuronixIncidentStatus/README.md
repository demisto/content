Update the status of the Securonix incident using the configuration provided in integration configuration.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Dependencies
---
This script uses the following commands and scripts.
* securonix-xsoar-state-mapping-get
* securonix-add-comment-to-incident

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| incident_id | Incident ID. |
| active_state_action | Securonix action name mapped with XSOAR's active state. |
| active_state_status | Securonix status to map with XSOAR's active state. |
| close_state_action | Securonix action name mapped with XSOAR's closed state. |
| close_state_status | Securonix status to map with XSOAR's close state. |
| only_active | Whether to only change the status of Securonix incident to XSOAR's respective active state. |

## Outputs
---
There are no outputs for this script.
