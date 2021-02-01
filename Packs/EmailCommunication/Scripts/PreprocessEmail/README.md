This script checks incoming emails from the incident type. If the emails contain an 8-digit hash in the email subject, the script will add the email response to the existing incident in the War Room with the "email-thread" tag. If there is no 8-digit hash in the email subject, the preprocessing will open a new incident for this email.

The script is a part of the Email Communication pack.

For more information about the preprocessing rules, refer to https://xsoar.pan.dev/docs/incidents/incident-pre-processing.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | preProcessing, email |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| attachments | The context path for attachments |
| files | The context path for files |

## Outputs
---
There are no outputs for this script.
