Syncs user information in the apps to which they are assigned in Okta. The playbook utilizes the "IAM Configuration" incident type to determine which integration instance the update needs to execute in. In addition it tracks errors if there are any, and assigns an analyst to review the incident when needed.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* AssignAnalystToIncident
* PrintErrorEntry
* IAMUpdateApplicationsField
* IsIntegrationAvailable
* SetAndHandleEmpty
* DeleteContext
* Set
* SetGridField

### Commands
* setIndicator
* okta-iam-list-user-applications
* closeInvestigation
* findIndicators
* setIncident
* demisto-lock-release
* okta-iam-get-configuration
* demisto-lock-get
* iam-update-user

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| UserRoleToAssignForFailures | The Cortex XSOAR role from which to assign users to the incident when a CRUD operation fails. This can be left empty to assign users from all roles. |  | Optional |
| UserAssignmentMethod | Determines the way in which user assignments will be decided in Cortex XSOAR for the failed incidents.<br/>Can be one of the following: "random", "machine-learning", "top-user", "less-busy-user", "online", "current".<br/>If left empty, users will be assigned randomly. |  | Optional |
| AssignOnlyOnCall | Determines whether to assign only users that are currently on a shift to failed incidents. Set to "true" to assign only users that are currently working, or set to "false" or leave empty to assign any user. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![IAM - App Update](./../doc_files/IAM_-_App_Update.png)