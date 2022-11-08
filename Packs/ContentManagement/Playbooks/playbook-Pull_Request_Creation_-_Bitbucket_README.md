This playbook creates a pull request using Bitbucket integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Bitbucket

### Scripts
* CommitFilesBitbucket
* Set
* SuggestBranchName
* DeleteContext

### Commands
* bitbucket-pull-request-list
* bitbucket-branch-create
* bitbucket-branch-get
* bitbucket-pull-request-update
* bitbucket-pull-request-create

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| PullRequestTemplate | Pull request description template. |  | Required |
| MainBranch | The name of the branch you want the changes pulled into, which must be an existing branch on the current repository. |  | Required |
| UserName | The user name in Bitbucket |  | Optional |
| Email | The email in Bitbucket |  | Optional |
| PackName | The name of the pack |  | Required |
| File | The File or Files to commit to the new or updated branch or pr |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Pull Request Creation - Bitbucket](../doc_files/Pull_Request_Creation_-_Bitbucket.png)