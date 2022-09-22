The script sends the email to the recipient's list, including the following information:
- The original email. 
- The name of the sender.
- The person to reply to.
- CC addresses, if they exist.
- BCC addresses, if they exist (Email Threads layout only)
- Attachments, if they exist.

For the "Email Communication" layout, the email body is taken from the incident 'notes,' and the email subject will contain the incident ID and the incident name.

For the "Email Threads" layout, email message details (recipients, subject, email body, etc) are set in Incident fields, as well as extracted from any previous messages on the same email thread.  Outbound email subjects will include a unique message ID and a custom subject line set when the first message in the thread is created.

The script is a part of the Email Communication pack.

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/playbooks/automations.html
](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/playbooks/automations.html)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 0.0.0 |

## Inputs
---

| **Argument Name**    | **Description** |
|----------------------| --- |
| files                | The context path for files. |
| attachment           | The context path for attachments. |
| service_mail         | The email address the emails are sent from. |
| mail_sender_instance | Name of the mail sender instance name for transmitting emails                                            |
| new_thread           | Specify whether to reply to an existing thread or start a new one.  Default value of 'n/a' is for 'Email Communication' type incidents only                                                                                                         |

## Outputs
---
There are no outputs for this script.
