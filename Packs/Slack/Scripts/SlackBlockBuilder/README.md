SlackBlockBuilder will format a given Slack block into a format readable by the SlackV3 integration. The script will also send the block to the given destination.

The Slack Block Kit Builder can be found [here](https://app.slack.com/block-kit-builder).

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | slack |
| Cortex XSOAR Version | 6.2.0 |

## Dependencies
---
This script uses the following commands and scripts.
* send-notification

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| blocks_url | The URL copied from Slack's Block Builder. |
| list_name | The name of the Cortex XSOAR list to use as the block's input. |
| user | The Slack user to which to send the message. Can be either an email address or a Slack user name. |
| channel | The Slack channel to send the message to. |
| channel_id | The Slack channel ID to send the message to. |
| task | The task to close with the reply. If empty, then no playbook tasks will be closed. |
| replyEntriesTag | Tag to add to email reply entries. |
| persistent | Indicates whether to use one-time entitlement or persistent entitlement. |
| reply | The reply to send to the user. Use the templates \{user\} and \{response\} to incorporate these in the reply. \(i.e., "Thank you \{user\}. You have answered \{response\}."\) |
| lifetime | Time until the question expires. For example - 1 day. When it expires, a default response is sent. |
| defaultResponse | Default response in case the question expires. |
| slackInstance | The instance of SlackV3 this script should use. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SlackBlockState | The State of the response from the user will be stored under this context path. | unknown |

#### Command Example using blocks_url
---
```text
!SlackBlockBuilder blocks_url=https://app.slack.com/block-kit-builder/T0DAYMVCM#%7B%22blocks%22:%5B%7B%22type%22:%22section%22
channel=random
task=4
replyEntriesTag=slackResponse
persistent=yes
```

#### Human Readable Output using blocks_url
---
```text
Message sent to Slack successfully.
Thread ID is: 1660645689.649679
```

#### Command Example using list_name
---
```text
!SlackBlockBuilder list_name=MySlackBlocksList channel=random task=4 replyEntriesTag=slackResponse persistent=yes
```

#### Human Readable Output using list_name
---
```text
Message sent to Slack successfully.
Thread ID is: 1660645689.649679
```
