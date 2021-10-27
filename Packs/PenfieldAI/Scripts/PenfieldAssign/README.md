PenfieldAssign will use the PenfieldGetAssignee integration to determine who an incident should be assigned to, then print the selected analyst to the War Room and overwrite the owner property.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | management, user, Utility |
| Cortex XSOAR Version | 5.5.0 |

## Dependencies
---
This script uses the following commands and scripts.
* penfield-api-call

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| assign | Whether this script should actually assign the incident by overwriting owner. Defaults to yes. |

## Outputs
---
There are no outputs for this script.

## Examples
---
!PenfieldAssign
!PenfieldAssign assign='Yes'
!PenfieldAssign assign='No'

#### Human Readable Output
incident assigned to: charles