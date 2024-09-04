This script closes duplicate incidents in XSOAR while resolving the assignment for the corresponding Vectra entity.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| page_size | Specify the number of incidents to close during a single execution. |
| note | The note to add to the closed incidents. |
| close_in_vectra | If set to true, the script will close the entity's assignment in Vectra platform. This option is supported only when instance of Vectra Detect integration is enabled. |
| incident_types | Specify the incident type(s) to close duplicate incidents. Supports comma-separated values. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| VectraDetectIncidents.count | The total number of incidents. | String |
| VectraDetectIncidents.closed_incident_ids | The IDs of the closed incidents. | String |
| VectraDetectIncidents.has_more_incidents | Whether there are more incidents to close. | Boolean |
