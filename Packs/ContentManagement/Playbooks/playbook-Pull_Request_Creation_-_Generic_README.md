This playbook creates a pull request from the content zip file.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Pull Request Creation - Github

### Integrations
This playbook does not use any integrations.

### Scripts
* ReadFile
* Set
* UnzipFile
* IsIntegrationAvailable
* PrintErrorEntry

### Commands
* send-notification
* getUsers
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ChannelName | The channel to which to send notifications. |  | Optional |
| PullRequestTemplate | Pull request description template. | ### Pull Request created in Cortex XSOAR<br/>**Created by:** {}<br/>**Pack:** {}<br/>**Branch:** {}<br/>**Link to incident in Cortex XSOAR:** {}<br/>{} <br/>--- | Required |
| MainBranch | The name of the branch you want the changes pulled into, which must be an existing branch on the current repository. | master | Required |
| GitIntegration | Which version control integration to use. | GitHub | Required |

## Playbook Outputs
---
There are no outputs for this playbook.
