The script sends the email to the recipient's list, with the following information:
- the original email 
- the name of the sender
- the person to reply to
- CC addresses, if they exist
- attachments, if they exist

The email body is taken from the incident 'notes', and the email subject will contain the incident ID and the incident name.

The script is a part of the Email Communication pack.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| files | The context path for files. |
| attachment | The context path for attachments. |
| service_mail | The email address the emails are sent from. |

## Outputs
---
There are no outputs for this script.
