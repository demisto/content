Asks a user a question via email and process the reply directly into the investigation.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | email |
| Demisto Version | 3.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| email | The email of the user to ask. |
| subject | The subject of the email. |
| message | The message to ask the user. |
| option1 | The first option for a user reply. The default is "yes". |
| option2 | The second option for the user reply. The default is "no". |
| additionalOptions | The comma delimited list of additional options if you have more than 2. |
| task | The task that should close with the reply. If none, then no playbook tasks will be closed. |
| roles | Sends mail to all users of these roles (a CSV list). |
| attachIds | The attachments. |
| bodyType | The type of email body to send. Can be, "text" or "HTML". |
| replyAddress | The reply address for html links. |
| replyEntriesTag | The tag to add on email reply entries. |
| persistent | Whether to use one-time entitlement or a persistent one. |
| retries | The number of times to try and create an entitlement in case of failure. |
| cc | The CC email address. |
| bcc | The BCC email address. |

## Outputs
---
There are no outputs for this script.
