Unassignes permission sets, permission set licenses and package licenses from a Salesforce account.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Salesforce_IAM

### Scripts
This playbook does not use any scripts.

### Commands
* salesforce-get-assigned-permission-set
* salesforce-get-assigned-permission-set-license
* salesforce-get-assigned-package-license
* salesforce-delete-assigned-permission-set-license
* salesforce-delete-assigned-permission-set
* salesforce-delete-assigned-package-license

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| salesforceId | Salesforce Unique ID |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IAM.Vendor | The Salesforce IAM commands' results. | unknown |

## Playbook Image
---
![Salesforce IAM - Post Deprovisioning](./../doc_files/Salesforce_IAM_-_Post_Deprovisioning.png)