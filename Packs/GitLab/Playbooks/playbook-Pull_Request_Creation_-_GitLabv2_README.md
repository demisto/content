This playbook creates a pull request using Github integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* CommitFilesGitlab
* SuggestBranchNameGitlab

### Commands
* gitlab-merge-request-create
* gitlab-branch-create
* gitlab-merge-request-list
* gitlab-branch-list
* gitlab-merge-request-list # https://gitlab.com/api/v4/projects/:project_id/merge_requests?iids[]=198&reviewer_id=Any&reviewer_id=None

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| PullRequestTemplate | Pull request description template. |  | Required |
| MainBranch | The name of the branch you want the changes pulled into, which must be an existing branch on the current repository. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.
