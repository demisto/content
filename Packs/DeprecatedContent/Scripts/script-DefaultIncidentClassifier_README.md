Classifies an incident from mail.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | ingestion |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| splunkSender | The email address from which Splunk sends emails to the mail listener. |
| nexposeSender | The email address from which Nexpose sends emails to the mail listener. |
| defaultIncidentType | The incident type to be set in case the email is not from Splunk nor Nexpose. |
| minRiskScore | |The argument passed as-is to `NexposeEmailParser`. See its documentation for details. |
| minVulnCount | The argument passed as-is to `NexposeEmailParser`. See its documentation for details. |
| sentinelOneSender | The email address from which sentinel one sends emails to the mail listener |
| sentinelOneIncidentType | The incident type to classify sentinel one events to. |

## Outputs
---
There are no outputs for this script.
