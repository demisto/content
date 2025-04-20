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
For more information, see the section about permissions here: For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.

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
| body_type            | The type of the email body. Can be either HTML or plain text. Default is HTML. |
| reputation_calc_async| Whether to calculate the reputation asynchronously. Default is false. |

## Outputs
---
There are no outputs for this script.

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.
