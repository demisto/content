Determine AWS account hierarchy by looking up parent objects until the organization level is reached.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* aws-org-parent-list
* aws-org-organization-unit-get
* aws-org-root-list
* aws-org-account-list

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| account_id | The unique identifier \(ID\) of the Amazon Web Services account that you want information about. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AWSHierarchy.id | ID of the account/OU/root object such as \`111111111111\`. | string |
| AWSHierarchy.level | Level in relation to the original AWS account such as account, 1, 2, etc. | string |
| AWSHierarchy.arn | ARN of the account/OU/root object such as \`arn:aws:organizations::111111111111:root/o-2222222222/r-3333\`. | string |
| AWSHierarchy.name | Human readable name of the account/OU/root object such as \`aws-account-n\`. | Unknown |
