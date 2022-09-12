Ask a user a question via email and process the reply directly into the investigation.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | email, emailthread |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| email | The email of the user to ask |
| subject | The subject for the email |
| message | The message to the user to ask |
| option1 | First option for a user reply. "yes" is the default. |
| option2 | Second option for the user reply. "no" is the default. |
| additionalOptions | A comma delimited list of additional options if you have more than 2 |
| task | Which task should we close with the reply. If none then no playbook tasks will be closed. |
| roles | Send mail to all users of these roles \(csv list\) |
| attachIds | Attachments |
| bodyType | Type of email body to send - text ot HTML |
| replyAddress | Address of reply for html links |
| replyEntriesTag | Tag to add on email reply entries |
| persistent | Indicates whether to use one-time entitlement or a persistent one |
| retries | Indicates how many times to try and create an entitlement in case of failure |
| cc | The CC email address |
| bcc | The BCC email address |
| playbookTaskID | Subplaybook ID, use $\{currentPlaybookID\} to get it from context, \`all\` to complete all tasks from all plabooks |
| integrationName | Name of the email integration used to send email |

## Outputs
---
There are no outputs for this script.
