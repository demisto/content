This playbook performs the same action as SlackAsk, but leverages `send-notification` and Slack Blocks to send fully customized questions and buttons, including customized responses to inquiries. Automatically creates a Slack channel with the responding user and assigned incident handler in the event of a response indicating that activity is unexpected. 

Assumes a binary Expected (Known/Trusted activity) and Unexpected (Unknown/Untrusted activity) response from the end user.

Recommended Playbook Customizations:
- Incident Channel name
- Context Message to Incident Channel
- Slack Block wrapper text (in Send Slack Blocks task)

Required Inputs:
- slack_user (username of the individual to be contacted in Slack)
- event_details (describe the event that is being investigated)
- event_data (event data to be included to give the user context)

Optional inputs:
- green_button_text  - text on the button which follows the Expected path
--- also green_button_response
- red_button_text - text on the button which follows the Unexpected path
--- also red_button_response

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SlackV3

### Scripts
* Set
* Sleep

### Commands
* addEntitlement
* slack-create-channel
* taskComplete
* send-notification

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| slack_user | Username of the user associated with the activity |  | Required |
| event_details | Describe the details of the event.  |  | Required |
| event_data | Provide event data that can create context for the user. You can use \\n to create line breaks.<br/><br/>Example: data_element_1:value_1\\n data_element_2:value_2\\n |  | Required |
| green_button_text | Supports emoji | Yes, this was me. :not-sus: | Optional |
| red_button_text | Supports emoji | No, this was not me. :not-sus: | Optional |
| green_button_response | Supports emoji | Thanks - we appreciate you! :burrwave: | Optional |
| red_button_response | Supports emoji | Oh no! Thanks for letting us know; we're moving to a private channel to discuss further `${incident.id}-aws-security-group-ingress-rule`. | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![2-button Slack Ask](Insert the link to your image here)