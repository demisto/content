This playbook creates a pull request using Bitbucket integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Bitbucket

### Scripts
* SuggestBranchName
* CommitFiles
* Set
* DeleteContext

### Commands
* bitbucket-pull-request-list
* bitbucket-branch-get
* bitbucket-pull-request-update
* bitbucket-branch-create
* bitbucket-pull-request-create

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| PullRequestTemplate | Pull request description template. |  | Required |
| MainBranch | The name of the branch you want the changes pulled into, which must be an existing branch on the current repository. |  | Required |
| PackName | The name of the pack |  | Required |
| File | The File or Files to commit to the new or updated branch or pr |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.
