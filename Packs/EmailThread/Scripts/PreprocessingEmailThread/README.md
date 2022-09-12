Preprocessing script for email communication layout.
This script checks if the incoming email contains an Incident ID to link the mail to an existing incident, and tags the email as "email-thread".
This script runs with elevated permissions. 
Cortex XSOAR recommends using the built-in RBAC functionality to limit access to only those users requiring access to this script.
For more information about the preprocessing rules, refer to: https://demisto.developers.paloaltonetworks.com/docs/incidents/incident-pre-processing

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | emailthread, preProcessing |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| attachments | Attachments |
| files | Files |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BaseScript.Output | \[Enter a description of the data returned in this output.\] | String |
