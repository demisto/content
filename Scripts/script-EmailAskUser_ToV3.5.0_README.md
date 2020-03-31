Asks a user a question via email and process the reply directly into the investigation.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | email |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| email | The email of the user to ask. |
| subject | The subject for the email. |
| message | The message to ask the user. |
| option1 | The first option for a user reply. The default is "yes". |
| option2 | The second option for the user reply. THe default is "no". |
| additionalOptions | A comma delimited list of additional options if you have more than 2. |
| task | The task to close with the reply. If none, then no playbook tasks will be closed. |
| roles | Sends a mail to all users of these roles (a CSV list). |
| attachIds | The attachments. |
| bodyType | The type of email body to send. Can be, "text" or "HTML". |
| replyAddress | The address to reply to with html links. |

## Outputs
---
There are no outputs for this script.
