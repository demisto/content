This script checks incoming emails from the incident type. If the emails contain an 8-digit hash in the email subject, the script will add the email response to the existing incident in the War Room with the "email-thread" tag. If there is no 8-digit hash in the email subject, the preprocessing will open a new incident for this email.

**Note:** In order to avoid performance issues, incoming emails will be added to an existing incident as "email-thread" only if the incident was **modified** in the last 60 days.
If you wish to extend this period, navigate to Settings->Advanced->Lists and add a new list with the name `XSOAR - Email Communication Days To Query`. In the `Data` field fill in a single number representing the number of days to query back, for example: 90.

The script is a part of the Email Communication pack.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | preProcessing, email |
| Cortex XSOAR Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| attachments | The context path for attachments |
| files | The context path for files |

## Outputs
---
There are no outputs for this script.
