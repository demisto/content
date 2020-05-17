Looks up incidents with a specified indicator. Uses `currentIncidentId` to omit the existing incident from output.

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
