Preprocessing script for Email Communication layout.
This script checks incoming emails from the incident type. If those emails contain an Incident Unique ID in the email subject, then the preprocessing will not open a new incident for this email. Instead, it will add the email response to the existing incident war room with the  "email-thread" tag.

**Note:** In order to avoid performance issues, incoming emails will be added to an existing incident as "email-thread" only if the incident was **modified** in the last 60 days.
If you wish to extend this period, navigate to Settings->Advanced->Lists and add a new list with the name `EmailCommunicationQueryWindow`. In the `Data` field fill in a single number representing the number of days to query back, for example: 90.

The script is a part of the Email Communication pack.

For more information about the preprocessing rules, please refer to https://xsoar.pan.dev/docs/incidents/incident-pre-processing. 

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
