The script gets the pack name as input and suggests an available branch name, for example:
pack name is "MyPack" the branch name will be "MyPack".
If a branch with the name "MyPack" exists, the script return "MyPack_1".


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
* Pull Request Creation - Gitlab
* Pull Request Creation - Bitbucket

## Inputs
---

| **Argument Name** | **Description** |
| --- |---|
| pack | The name of the pack. |
| use_command | Which command to use. Possible commands: * gitlab-branch-list * GitHub-get-branch * bitbucket-branch-get |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AvailableBranch | Available branch name based on the pack name. | string |
