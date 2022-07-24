This playbook creates a pull request from content zip file.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* SuggestBranchName
* Set
* ReadFile
* IsIntegrationAvailable
* CommitFiles
* UnzipFile

### Commands
* GitHub-list-branch-pull-requests
* setIncident
* GitHub-create-pull-request
* GitHub-create-branch
* send-notification
* GitHub-request-review
* closeInvestigation
* GitHub-get-branch
* getUsers

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SlackChannel | Slack channel name to send the notifications. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Pull Request Creation](../doc_files/Pull_Request_Creation.png)