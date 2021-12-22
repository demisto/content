Asks a user a question on `Mattermost` and expects a response. The response can also close a task, (this can be conditional) in a playbook.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | mattermost |


## Dependencies
---
This script uses the following commands and scripts.
* send-notification

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| user | The Mattermost user to ask. Can be, "email" or "mattermost username". |
| message | The message to ask the user. |
| option1 | The first option for a user to reply. The default is "yes". |
| option2 | The second option for the user reply. The default is "no". |
| task | Whether the task should close with the reply. If "none" then no playbook tasks will be closed. |
| replyEntriesTag | The tag to add on to the email reply entries. |
| persistent | Whether to use a one-time entitlement or a persistent one. |

## Outputs
---
There are no outputs for this script.
