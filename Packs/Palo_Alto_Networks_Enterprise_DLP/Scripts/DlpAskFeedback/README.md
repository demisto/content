Sends a message via Slack to the user whose file upload violated DLP policies and triggered the incident.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.5.0 |

## Dependencies
---
This script uses the following commands and scripts.
* send-notification

## Used In
---
This script is used in the following playbooks and scripts.
* DLP Incident Feedback Loop

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| messenger | The messenger to use for sending notification, |
| file_name | The name of the file that triggered the incident. |
| data_profile_name | The name of the DLP data profile that detected the violation. |
| app_name | The application that performed the upload. |
| task | A manual task that this task can close. |
| user_display_name | The user name displayed in the Slack message. |
| user_id | The user ID to identify the recipient in Slack. |
| snippets | The snippets of the violation. |
| include_violation_detail | Whether to include violation details in the message. |
| question_type | Whether to ask the user about the file content or about exemption. |

## Outputs
---
There are no outputs for this script.
