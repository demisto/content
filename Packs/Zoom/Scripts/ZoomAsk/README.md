Sends a message (question) to either a user (in a direct message) or to a channel. The message includes predefined reply options. The response can also close a task (might be conditional) in a playbook.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Zoom |
| Version | 5.5.0 |

## Use Case
---
This automation allows you to ask users in Zoom (including users who are external to Cortex XSOAR) questions, have them respond and 
reflect the answer back to Cortex XSOAR.

## Dependencies
---
Requires an instance of the Zoom integration with Long Running instance checked.

This script uses the following commands and scripts.
send-notification

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| user | The Zoom user to whom to send the message. Can be either an email address or a Zoom user_id. |
| channel_id | The Zoom channel_id to which to send the message. |
| message | The message to send to the user or channel. |
| option1 | The first reply option. The default is "Yes" with a blue button. To change the color of the button, add the pound sign \(\#\) followed by the name of the new color \(blue, red, or black\). The default color is "Blue". For example, "Yes\#blue". |
| option2 | The second reply option. The default is "No" with a red button. To change the button color, add the pound sign \(\#\) followed by the name of the new color \(green, red, or black\). The default color is "red". For example, "No\#red". |
| task | The task to close with the reply. If empty, then no playbook tasks will be closed. |
| persistent | Indicates whether to use one-time entitlement or persistent entitlement. |
| responseType | How the user should respond to the question. |
| additionalOptions | A comma-separated list of additional options in the format of "option\#color", for example, "maybe\#red". The default color is "black". |
| reply | The reply to send to the user. Use the templates \{user\} and \{response\} to incorporate these in the reply. \(i.e., "Thank you \{user\}. You have answered \{response\}."\) |
| lifetime | Time until the question expires. For example - 1 day. When it expires, a default response is sent. |
| defaultResponse | Default response in case the question expires. |

## Outputs
---
There are no outputs for this script.

## Guide
---
The automation is most useful in a playbook to determine the outcome of a conditional task - which will be one of the provided options.
It uses a mechanism that allows external users to respond in Cortex XSOAR (per investigation) with entitlement strings embedded within the message contents.
![SlackAsk](https://user-images.githubusercontent.com/35098543/66044107-7de39f00-e529-11e9-8099-049502b4d62f.png)

The automation can utilize the interactive capabilities of Zoom to send a form with buttons. 
This requires the external endpoint for interactive responses to be available for connection. (See the Zoom integration documentation for more information).
You can also utilize a dropdown list instead, by specifying the `responseType` argument.

## Notes
---