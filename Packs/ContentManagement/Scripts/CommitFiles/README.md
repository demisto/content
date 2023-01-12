This script gets content files as input from the context, commits the files in the correct folder and creates the pull request text.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Pull Request Creation - Github
* Pull Request Creation - Bitbucket

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| files | The files to commit. |
| branch | The branch name to commit. |
| git_integration | Which version control integration to use. |
| pack | The name of the pack. |
| user | The current user details from the command "getUsers". |
| comment | Short description to add to the pull request text. |
| template | Pull request description template. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PR_text | The pull request text. | string |
