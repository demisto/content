Checks whether an older open/pending "Panorays Finding" incident already exists for the same Finding ID, by calling getIncidents server-side and returning a single explicit boolean output. Used by the Panorays Finding - Triage and Response playbook to avoid a race where two incidents created at nearly the same time could each see the other as already-open and both close as Duplicate - only the newer incident \(higher ID\) is ever told a duplicate exists.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| finding_id | The Panorays Finding ID to search for. |
| incident_id | The current incident's ID. Only other incidents with a lower ID are considered a match. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PanoraysDuplicateCheck.OlderDuplicateExists | Whether an older open/pending duplicate incident exists for this Finding ID. | Boolean |
