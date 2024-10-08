# DSPM Multi-Cloud Risk Remediation

## Overview

The **DSPM Multi-Cloud Risk Remediation** ensures efficient incident resolution and compliance with security policies by guiding the user through decision points based on incident type, such as empty storage assets or assets open to the world. It concludes by updating the incident status and closing the playbook upon resolution.
Whenever a new incident will get created DSPM Mulit-Cloud Risk Remediation playbook will get trigger and send slack notification to user. User will get a form-type message where they can select an action depending on their requirements.

## Key Features

- Fetch asset data from DSPM
- Send Slack notifications to users about the risk being generated.
- User will get a form of action where they get option to select action they want to perform on the risk.
- Get response from user and move forward according to the user specified action.
- Update the user by sending slack notification in case of successfull run or any failure.
- Tracks and logs any encountered errors during the process.
  
## Playbook Flow

1. **Obtain relevant risk fields from the incident**: The playbook fetch the incident from webhook and map them into relevant risk fields.
2. **Create slack block list**: The playbook create a slack message and save it in the XSOAR List.
3. **Send slack notification to user**: The playbook will send the slack notification to user and get the response from the user.
4. **Check Valid or Invalid User response**: The playbook will check the user reponse and perform the action accordingly.
5. **Error Handling**: If errors occur during the mitigation process, a notification is sent, and the user is informed via Slack.
6. **Add to re-run list**: The playbook will add the incident to re-run in case of any failure.
7. **Delete slack block list**: The playbook will delete the slack block from the XSOAR list.
8. **Final Notification**: A final Slack notification is sent, confirming either successful or failed run.

## Playbook Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

| **Sub-playbook Name**                | **Description**                                                                                                              |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------                       |
| DSPM Send Slack Notification to User | Send slack notification to user and get the user response.                                                                   |
| DSPM notify user in case of error    | Notify user about the error and add incident in re-run incident list.                                                        |
| DSPM Valid User Response             | Perform user specificed action and notify user.                                                                              |
| DSPM Invalid User Response           | Notify user about the invalid response and re-run the playbook immedietly                                                    |


### Integrations

* Prisma Cloud DSPM
* Atlassian Jira v3
* AWS - S3
* Azure Storage Container
* Google Cloud Storage
* Slack v3
* Core REST API

### Scripts

| **Script Name**                | **Description**                                                                                                                    |
| ------------------------------- | ------------------------------------------------------------------------------------------------------                            |
| DSPMExtractRiskDetails          | Extracts risk details from an incident object, processes asset tags, and sets the user's Slack email notifications                |
| DSPMCheckAndSetErrorEntries     | Checks for error entries in the previous task and sets errors in the XSOAR context.                                               |
| DSPMIncidentList                | Manages incidents in a list by adding or deleting incidents based on the provided action.                                         |
| DSPMCreateRiskSlackBlocks       | Create the slack block list on XSOAR.                                                                                             |
| DSPMRemoveSlackBlockList        | Removes the slack block list from XSOAR.                                                                                          |
| DSPMOverwriteListAndNotify      | Overwrites a list's value and sends a Slack notification with Jira Ticket details.                                                |
| SlackBlockBuilder               | Script send notifications to user via slack                                                                                       |


## Playbook Inputs

---

| **Name**               | **Description**                              | **Default Value** | **Required** |
| -------------------------- | -------------------------------------------- | ----------------- | ------------ |
| `incident_object`          | Incident data fetched from DSPM webhook.     |                   | Required |
| `dspm_incident`            | Incident object JSON.                        |                   | Optional |
| `block_list_name`          | List to overwrite in case of failure         |                   | Required |
| `message`                  | Message to be send to user                   |                   | Required |
| `action`                   | Action to perform on DSPM Incident           | add               | Optional |
| `lastCompletedTaskEntries` | Entry Id of last completed task              |                   | Required |

## Playbook Outputs

---
The playbook generates the following outputs:
- Create risk field object from the incident
- Create slack block list.
- Notifications sent via Slack.
- Add/Delete incident from re-run list.
- Remove slack block list


## Usage Instructions

1. Extracts risk details from an incident object, processes asset tags, and sets the user's Slack email notifications
2. Checks for error entries if not then create slack block message and in case of any error, notify user about the error and add the incident in the re-run list.
3. Send slack notification to user to perfrom any specific action for that risk.
4. In case of invalid user response re-run the playbook.
5. In case of valid response, perform the user specified action and notify user.
4. Remove the slack block message from the XSOAR list.

## Playbook Image

---

![DSPM Multi-Cloud Risk Remediation](../doc_files/DSPM_Multi_Cloud_Risk_Remediation.png)