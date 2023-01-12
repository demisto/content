Asks a user a question via Salesforce Chatter and process the reply directly into the investigation.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | - |


## Dependencies
---
This script uses the following commands and scripts.
* salesforce-push-comment

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| persistent | Indicates whether to use a one-time entitlement or a persistent one. |
| replyEntriesTag | The tags to add on comment reply entries. |
| retries | The number of times to try and create an entitlement when there is a failure. |
| task | The task that should be closed with the reply. If none, then no playbook tasks will be closed. |
| option1 | The first option for a user reply. |
| option2 | The second option for the user reply. |
| oid | The object ID of the subject. |
| additionalOptions | A comma delimited list of additional options (in cases where more than 2 options are needed). |
| text | The text of the chatter comment. If not given, a default post message will be generated based on option arguments. |
| link | The link to add to the message. |

## Outputs
---
There are no outputs for this script.
