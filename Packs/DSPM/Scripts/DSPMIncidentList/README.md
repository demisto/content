This automation script manages incidents in a list by adding or deleting incidents based on the provided action.
For incidents older than the configured time limit (default is 48 hours), the script performs a cleanup by removing
the incident from the list. Additionally, the script supports adding new incidents to the list if they do not already exist.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| incident_data | Incident data of a specific asset. |
| action | Action to perform on incident list i.e :- add or delete list. |
| incident_list | DSPM Incident list data. |
| rerun_time | Re-run time to be checked of an incident to delete or not. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| listStatus | Updated incident list status. | Unknown |
