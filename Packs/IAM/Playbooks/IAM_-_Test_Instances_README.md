This playbook is used to test configured Identity Lifecycle Management integration instances by executing generic CRUD commands. If one of the instances fails to execute a command, the playbook will fail and the errors are printed to the Print Errors task at the end of the playbook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* PrintErrorEntry
* IAMInitADUser
* IAMInstancesList

### Commands
* iam-create-user
* iam-update-user
* iam-disable-user
* iam-get-user
* iam-enable-user

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| userprofile | A test user profile json, e.g. '\{"email": "test@paloaltonetworks.com", "givenname": "test", "surname": "test", "locationregion": "Americas"\}'. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![IAM - Test Instances](https://user-images.githubusercontent.com/38749041/97545670-01ddb400-19d4-11eb-9115-c021561605d3.png)