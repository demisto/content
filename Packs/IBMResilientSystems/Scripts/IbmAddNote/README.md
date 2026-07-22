Use this script to add a note with a tag (the "Note tag to IBM" defined in the instance configuration) as an entry in Cortex XSOAR, which will then be mirrored as a note to a IBM QRadar SOAR incident. This script should be run within an incident.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Inputs

---

| **Argument Name** | **Description**                                                                                                        |
|-------------------|------------------------------------------------------------------------------------------------------------------------|
| note              | Note to be added to the IBM QRadar SOAR incident.                                                                      |
| tags              | The note tag. Use the note entry tag \(defined in your instance configuration\) to mirror the note to IBM QRadar SOAR. |

## Outputs

---
There are no outputs for this script.
