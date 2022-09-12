Extract user's response from EmailAskUser reply. Returns the first textual response line of the provided entry that contains the reply body. Use ${lastCompletedTaskEntries} to analyze the previous playbook task containing the user's reply.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Condition, emailthread |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| responseEntryId | Entry ID where EmailAskUser will complete when user replies |

## Outputs
---
There are no outputs for this script.
