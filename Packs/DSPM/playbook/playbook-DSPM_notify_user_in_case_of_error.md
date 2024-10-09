# DSPM notify user in case of error

## Overview

The **DSPM notify user in case of error** is designed to notify users in case of any error. This playbook focuses on sending slack notification to user with an error message occured while running the previous playbook steps. This playbook also add incident in the re-run incident list.

## Key Features

- Get the error message from the previous task.
- Create a slack block message in the XSOAR list.
- Add incident in the re-run incident list.
- Sends Slack notifications to users regarding failure.
- Remove the slack block message list.
  
## Playbook Flow

1. **Notify user in case of error**: The playbook get the error message from the previous task and send slack message to user.
2. **Add incident for re-run**: The playbook add incident in the re-run incident list.
3. **Remove the slack block list**: The playbook removes the slack block message from the XSOAR list.

## Steps

1. **Start**:
   - The playbook starts and create slack block list in XSOAR.

3. **Slack Notification**:
   - Notify user about the error.

4. **Re-run incident list**:
   - Add incident to re-run incident list.

5. **Remove block**:
   - Remove slack block message from the XSOAR List.


## Playbook Dependencies

This playbook uses the following integrations, and scripts.

### Integrations

* Prisma Cloud DSPM
* Slack v3
* Core REST API

## Key Commands and Scripts Used

- `DSPMNotifyUser`: Create a slack block message in XSOAR list.
- `SlackBlockBuilder`: Sends a Slack notification with a formatted block to the user.
- `DSPMIncidentList`: Add incident into re-run incident list.
- `DSPMRemoveSlackBlockList`: Remove the slack block messgae from XSOAR list.

## Playbook Inputs

| **Name**             | **Description**                                         | **Required** |
|----------------------|---------------------------------------------------------|--------------|
| `dspm_incident`     | Object containing details about the risk            | Required          |
| `message`             | Error message from the last task         | Required          |
| `block_list_name`     | The block list to overwrite in case of failure or error | Required          |
| `lastCompletedTaskEntries` | Entries from the last completed task               | Required          |
| `action` | Action needed to performed on DSPM Incident list  | add | Optional |

## Outputs

The playbook generates the following outputs:
- Create a slack block message list in XSOAR..
- Notifications sent via Slack.
- Add incident in the re-run list.
- Remove the slack block message list from XSOAR.

## Conclusion

This playbook will notify the user if there is any error and add the incident in the re-run incident list.

---