Asks a user a question on Slack and expects a response. The response can also close a task (can be conditional) in a playbook.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | slack |
| Demisto Version | 0.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* slack-send

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| user | The slack user to ask. Can be, "email" or "slack username". |
| message | The message to ask the user. |
| option1 | The first option for a user reply. The default is "yes". |
| option2 | The second option for the user reply. The default is "no". |
| task | The task chosen to close with the reply. If none then no playbook tasks will be closed. |

## Outputs
---
There are no outputs for this script.
