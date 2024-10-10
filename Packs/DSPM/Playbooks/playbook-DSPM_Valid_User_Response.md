# DSPM Valid User Response Playbook

## Overview
This playbook handles user responses for various risk findings detected in cloud environments. Depending on the user action, it triggers different workflows such as remediation for sensitive assets or empty storage assets, creating Jira tickets, or handling no response from the user. The playbook is integrated with Slack for notifications and Jira for ticket management.

## Playbook ID
`08655808-4525-45cd-8540-48e7d75e6610`

## Description
This playbook manages the workflow based on user responses to risk findings. It allows the user to choose actions like remediation, creating Jira tickets, or ignoring the response. If no response is received, it triggers a follow-up action to notify the user and update the incident list for re-run if necessary.

### Actions Based on User Responses:
1. **Jira Action**: Creates a Jira ticket for tracking the risk.
2. **Remediation Action for Empty Storage Assets**: Initiates the remediation process for empty storage assets.
3. **Remediation Action for Sensitive Assets Open to the World**: Executes remediation actions for sensitive assets with public exposure.
4. **No Response from User**: If no response is received, the playbook sends a Slack notification and updates the incident list for future follow-up.

## Steps

1. **Start**:
   - The playbook starts and awaits user action.

2. **Condition - User Action**:
   - The playbook checks the value of `User.Action`. It proceeds based on the user's selection or lack of response.

3. **Jira Action**:
   - If the user selects `jira`, the playbook initiates the `DSPM Jira Ticket Creation` sub-playbook to create a ticket in Jira.

4. **Remediation for Empty Storage Assets**:
   - If the user selects `remediate` and the risk type is `Empty storage asset`, the playbook runs the `DSPM Remediation Playbook for Empty Storage Asset`.

5. **Remediation for Sensitive Assets Open to the World**:
   - If the user selects `remediate` and the risk type is `Sensitive asset open to world`, the playbook triggers the `DSPM Remediation Playbook for Sensitive Asset Open to World`.

6. **No Response from User**:
   - If the user fails to respond, the playbook sends a Slack notification to inform the user and updates the incident list for future handling.

7. **Slack Notifications**:
   - The playbook uses Slack to notify the user of important actions, such as the creation of a Jira ticket, successful remediation, or failure to respond in time.

8. **Add Incident for Re-Run**:
   - If no response is received, the playbook adds the incident to the incident list for a potential re-run.

## Key Commands and Scripts Used

- `SlackBlockBuilder`: Sends a Slack notification with a formatted block to the user.
- `DSPMOverwriteListAndNotify`: Sends a Slack notification when no response is received.
- `DSPM Jira Ticket Creation`: Sub-playbook to create a Jira ticket.
- `DSPM Remediation Playbook for Empty Storage Asset`: Sub-playbook for remediating empty storage assets.
- `DSPM Remediation Playbook for Sensitive Asset Open to World`: Sub-playbook for remediating sensitive assets with public exposure.
- `DSPMIncidentList`: Updates the incident list for potential re-runs.

## Notifications
The playbook provides real-time updates to the relevant stakeholders via Slack messages, detailing:
- The success or failure of Jira ticket creation.
- Remediation actions taken for cloud assets.
- No response notifications if the user fails to act.

## Error Handling
The playbook includes error handling mechanisms at each step. Errors are logged, and relevant stakeholders are notified via Slack. Additionally, failed incidents are added to a list for future review and re-run if necessary.

## Script Descriptions and Usage

### 1. `SlackBlockBuilder` 
- **Description**: This script builds a Slack message block and sends it to a specified Slack user using the SlackV3 integration.
- **Usage**: Provide the Slack user email (`user`) and block list name (`list_name`) for sending the notification.

### 2. `DSPMOverwriteListAndNotify` 
- **Description**: This script is used when no response is received from the user. It overwrites a list and notifies the user via Slack.
- **Usage**: Provide the `incident_id`, `list_name`, and a custom `message` to notify the user about the inactivity.

### 3. `DSPMIncidentList` 
- **Description**: This script adds incidents to a list for a potential re-run.
- **Usage**: Use the action `add` and pass the `incident_data` to log the incident for future re-runs.

### 4. Sub-Playbooks:
   - **DSPM Jira Ticket Creation**: Automatically creates Jira tickets to track identified risks.
   - **DSPM Remediation Playbook for Empty Storage Asset**: Executes the remediation steps for empty storage assets.
   - **DSPM Remediation Playbook for Sensitive Asset Open to World**: Handles the remediation of sensitive assets with public exposure.