# DSPM Invalid User Response Playbook

## Overview
This playbook re-run the incident in case if user has provided invalid response. It notify the user first about the invalid response and then re-send the slack message to user to perform action on that risk.

## Key Features

- Notify the user about invalid response.
- Send Slack notifications to users to perform various action on the risk.
- User will get a form of action where they get option to select action they want to perform on the risk.
- Get response from user and move forward according to the user specified action.
- Update the user by sending slack notification in case of successfull run or any failure.
- Tracks and logs any encountered errors during the process.

## Steps

1. **Start**:
   - The playbook starts and create slack block list in XSOAR.

3. **Slack Notification**:
   - Notify user about the invalid response.

4. **Create a form of action**:
   - Create a form of action where user get option to select action they want to perform on the risk.

5. **Slack Notification**:
   - If slack block message got created successfully then `DSPM Send Slack Notification to User` initiate to send slack notification to user and get response from slack.

6. **Notify in case or error**:
   - If slack block message got any error then `DSPM notify user in case of error` initiate to notify user about the error.


## Key Commands and Scripts Used

- `DSPMOverwriteListAndNotify`: Sends a Slack notification when no response is received.
- `DSPMCreateRiskSlackBlocks`: Create form of action for the specific risk to send user.
- `SlackBlockBuilder`: Sends a Slack notification with a formatted block to the user.
- `DSPM Send Slack Notification to User`: Sub-playbook to send user notification.
- `DSPM notify user in case of error`: Sub-playbook to notify user about the error.


## Notifications
The playbook provides real-time updates to the relevant stakeholders via Slack messages, detailing:
- The invalid user response.
- Creating form of action.
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

### 3. `DSPMCreateRiskSlackBlocks` 
- **Description**: This script create the slack block message for a specific risk.
- **Usage**: Provide the `dspm_incident` data to create form of actio.

### 4. Sub-Playbooks:
   - **DSPM Send Slack Notification to User**: Send notification to user and get user response.
   - **DSPM notify user in case of error**: Notify user about the error and add incident for re-run.