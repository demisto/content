Use this script to add a note with a tag (the "Note tag to Splunk" defined in the instance configuration) as an entry in Cortex XSOAR, which will then be mirrored as a note to a Splunk finding. This script should be run within an incident.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| note | Note to be added to the Splunk finding. |
| tag | The note tag. Use the note entry tag \(defined in your instance configuration\) to mirror the note to splunk. |

## Outputs

---
There are no outputs for this script.
