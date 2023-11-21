Looks up incidents with a specified indicator. Uses `currentIncidentId` to omit the existing incident from output.

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator | The indicator to search for. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IncidentsWithIndicator.Indicator | The indicator that was found in other incidents. | Unknown |
| IncidentsWithIndicator.incidentIDs | The incident IDs that the indicator was found in. | Unknown |
