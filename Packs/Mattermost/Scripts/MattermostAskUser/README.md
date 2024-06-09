Ask a user a question on Mattermost and expect a response. The response can also close a task (might be conditional) in a playbook.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | mattermost |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* send-notification

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| user | The Mattermost user to ask. Can be either an email or Mattermost username. |
| message | The message to ask the user. |
| option1 | First option for a user reply. "yes" is the default. |
| option2 | Second option for the user reply. "no" is the default. |
| task | Which task should we close with the reply. If none, then no playbook tasks will be closed. |
| replyEntriesTag | Tag to add on email reply entries. |
| persistent | Indicates whether to use one-time entitlement or a persistent one. |
| reply | The reply to send to the user. Use the templates \{user\} and \{response\} to incorporate these in the reply. \(i.e., "Thank you \*\*\{user\}\*\*. You have answered \*\*\{response\}\*\*."\). |
| lifetime | Time until the question expires. For example - 1 day. When it expires, a default response is sent. Default value is 1 day. |
| defaultResponse | Default response in case the question expires. |

## Outputs

---
There are no outputs for this script.
