Send a team member or channel a question with predefined response options on Microsoft Teams. The response can be used to close a task (might be conditional) in a playbook.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | microsoftteams |
| Cortex  XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* send-notification

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| message | Question \(message\) to send to the specified team member or channel. |
| persistent | Indicates whether to use one-time entitlement or persistent entitlement. |
| option1 | First reply option. |
| option2 | Second reply option. |
| additional_options | A CSV list of additional options \(in case more than 2 options are required\). |
| team_member | Team member to which to send the question. |
| task_id | Task ID of the playbook task to close with the reply. If not provided, no playbook task will be closed. |
| channel | Channel to which to send the question. |

## Outputs
---
There are no outputs for this script.

## Usage

The MicrosoftTeamsAsk script sends a message, such as operation approval or information retrieval, in a question format from Cortex XSOAR to Microsoft Teams. The message must have at least two options. For example, "yes" and "no".

After the question is answered in Microsoft Teams, the response is sent to the Demisto server, which appears as a conditional task in a playbook with response options as conditions. Depending on the response, the workflow may continue. For example, you define the following arguments: 

* `option1`: yes
* `option2`: no 

If a team member responds "yes" the playbook continues running the "yes" branch.

If a task ID is included in the script, and the task condition is met, the playbook closes as soon as a response is received.
