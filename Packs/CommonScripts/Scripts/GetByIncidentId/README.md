Gets a value from the specified incident's context.

**Note** This script can only retrieve incident fields that appear under the investigation context. To get incident basic information, use the ``searchIncidentsV2`` automation to pull the relevant incident and extract the needed fields from the automation output.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| incident_id | The ID of the incident from which to get context values. The default is the current incident. |
| get_key | The key to get |
| set_key | The key to set. The default is "get_key". |

## Outputs

---
There are no outputs for this script.
