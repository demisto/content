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
| team | The team in which to mirror the Cortex XSOAR investigation. If not specified, the default team configured in the integration parameters will be used. |

## Outputs

---
There are no outputs for this script.

## Usage

---

The MicrosoftTeamsAsk script sends a message, such as operation approval or information retrieval, in a question format from Cortex XSOAR to Microsoft Teams. The message must have at least two options. For example, "yes" and "no".

After the question is answered in Microsoft Teams, the response is sent to the Cortex XSOAR server, which appears as a conditional task in a playbook with response options as conditions. Depending on the response, the workflow may continue. For example, you define the following arguments:

* `option1`: yes
* `option2`: no

If a team member responds "yes" the playbook continues running the "yes" branch.

If a task ID is included in the script, and the task condition is met, the playbook closes as soon as a response is received.

To use `MicrosoftTeamsAsk` via playbook:

1. Add the `MicrosoftTeamsAsk` script to a playbook as a task.
2. In the `message` argument, specify the message to be sent.
3. Configure the response options by filling out the `option1` and `option2` arguments (default values are 'Yes' and 'No').
4. Either a team_member or a channel must be specified.
5. In the `MicrosoftTeamsAsk` task, pass a tag value to the `task_id` argument.

All other inputs are optional.
At some point at the playbook, after running `MicrosoftTeamsAsk`, add a manual conditional task, which holds up the playbook execution until the response is received from Teams.
The condition names must match the response options you passed in to `MicrosoftTeamsAsk`.
In order to tie the conditional task back to `MicrosoftTeamsAsk`, add the same tag from the fifth step to the conditional task (under the "Details" tab of the task). The conditional task will be marked as completed when a user responds to the `MicrosoftTeamsAsk` form.

## Notes

---

* `MicrosoftTeamsAsk` will not work when run in the playbook debugger. This is because the debugger does not generate entitlements, since they must be tied to an investigation. Entitlements are needed to track the response.
