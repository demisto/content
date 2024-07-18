Sends a message (question) to either user (in a direct message) or to a channel. The message includes predefined reply options. The response can also close a task (might be conditional) in a playbook.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | googleChat |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* send-notification

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| user | The recipient of the message |
| message | The message to send to the user or channel. |
| space_id | The ID of the space where the message will be send to. |
| option1 | The first reply option. The default is "Yes" with a blue button. To change the color of the button, add the pound sign \(\#\) followed by the name of the new color \(Blue, Green, or Red\). For example, "Yes\#blue". |
| option2 | The second reply option. The default is "No" with a red button. To change the button color, add the pound sign \(\#\) followed by the name of the new color \(Blue, Green, or Red\). For example, "No\#red". |
| additional_options | A CSV list of additional options. |
| task_id | The task_id to close with the reply. If empty, then no playbook tasks will be closed. |
| lifetime | Time until the question expires. For example - 1 day. When it expires, a default response is sent. |
| response_type | How the user should respond to the question. |
| default_reply | The default reply if the user does not response after lifetime exceeded. |

## Outputs

---
There are no outputs for this script.
