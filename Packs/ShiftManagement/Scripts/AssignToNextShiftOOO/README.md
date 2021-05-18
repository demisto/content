Randomly assigns the active incidents to on-call analysts (requires shift management). This automation works with the other out-of-office automations to ensure only available analysts are assigned to the active incidents. 

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Shift Management, ooo |
| Demisto Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
Assign Active Incidents to Next Shift V2

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| incidentIds | A comma-separated list of active incident IDs to assign to the next shift, for example, 1,2,3,4. |
| listname | The name of the out-of-office list. Default is "OOO List". |

## Outputs
---
There are no outputs for this script.
