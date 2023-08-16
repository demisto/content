This playbook creates a pull request using the Azure DevOps integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
Azure DevOps

### Scripts
* SuggestBranchName
* CommitFiles
* Set
* DeleteContext

### Commands
* azure-devops-branch-list
* azure-devops-branch-create
* azure-devops-pull-request-create
* azure-devops-pull-request-list
* azure-devops-pull-request-update
* azure-devops-file-list
* azure-devops-file-update
* azure-devops-file-create

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- |--------------|
| PullRequestTemplate | Pull request description template. |  | Required     |
| MainBranch | The name of the branch you want the changes pulled into, which must be an existing branch on the current repository. |  | Optional     |
| PackName | The name of the pack. |  | Required     |
| File | The file or files to commit to the new or updated branch or pull request. |  | Required     |

## Playbook Outputs
---
There are no outputs for this playbook.
Creating a branch (with the azure-devops-branch-create command) creates a new file due to API limitations ("create_branch.txt").
