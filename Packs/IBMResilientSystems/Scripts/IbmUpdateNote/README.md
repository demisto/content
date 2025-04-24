Use this script to update a note in an IBM QRadar SOAR incident. This script should be run within an incident.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Dependencies

---
This script uses the following commands and scripts.

* rs-update-incident-note
* IBM Resilient Systems

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| note_id | ID of the note to be updated. |
| note_body | Note body. |
| tags | The note tag. Use the note entry tag \(defined in your instance configuration\) to mirror the note to IBM QRadar SOAR. |

## Outputs

---
There are no outputs for this script.
