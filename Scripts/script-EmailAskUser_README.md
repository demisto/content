Asks a user a question via email and process the reply directly into the investigation.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | email |
| Demisto Version | 4.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| email | The email of the user to ask. |
| subject | The subject for the email. |
| message | The message sent to the user you are going to ask. |
| option1 | The first option for a user reply.The default is "yes". |
| option2 | The second option for the user reply. The default is "no". |
| additionalOptions | The comma delimited list of additional options if there are more than 2. |
| task | Which task the reply will close. If none, then no playbook tasks will be closed. |
| roles | Send mail to all users of these roles (a CSV list). |
| attachIds | The attachments. |
| bodyType | The type of email body to send. Can be, "text" or "HTML". |
| replyAddress | The reply address for the html links. |
| replyEntriesTag | The tag to add on email reply entries. |
| persistent | Whether to use one-time entitlement or a persistent one. |
| retries | How many times to try and create an entitlement in case of a failure. |
| cc | The CC email address. |
| bcc | The BCC email address. |
| playbookTaskID | The subplaybook ID, use `${currentPlaybookID}` to get from the context, `all` to complete all tasks from all plabooks |

## Outputs
---
There are no outputs for this script.
