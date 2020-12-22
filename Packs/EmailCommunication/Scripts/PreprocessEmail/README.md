Preprocessing script for Email Communication layout.
This script checks incoming emails and checks if they are a reply to a previously ingested email,
based on having the incident ID in the subject, or finding the relevant Message ID using the References header.

If found, it will add the email response to the existing incident war room with the  "email-thread" tag,
otherwise a new incident will be created as normally.

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
