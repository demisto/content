The script sends email massages with the enabled configured mail sender integration.
The script will send the email to the recipient's list, consists of the original email from, email to, and the email CC if exist. The email body will be taken from the incident 'notes,' and the email subject will contain the incident ID and the incident name.

The script is a part of a pack name Email Communication.

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
| files | The context path for files |
| attachment | The context path for attachments |
| service_mail | The email address the emails will send from |

## Outputs
---
There are no outputs for this script.
