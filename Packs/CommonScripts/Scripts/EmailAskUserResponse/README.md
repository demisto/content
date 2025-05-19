Extract a user's response from `EmailAskUser reply`. Returns the first textual response line of the provided entry that contains the reply body. Use `${lastCompletedTaskEntries}` to analyze the previous playbook task containing the user's reply.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Condition |


## Inputs
---

| **Argument Name** | **Description** |
|-------------------| --- |
| responseEntryId   | The entry ID where `EmailAskUser` will complete when the user replies. |
| prefix            | Text to remove from the start of the answer. If the response contains a known prefix that should be removed, this argument should be used. |
| suffix            | Text to remove from the end of the answer. If the response contains a known suffix that should be removed, this argument should be used. |

## Outputs
---
There are no outputs for this script.
