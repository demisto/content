This playbook is responsible for collecting and enriching data on Identity Access Management (IAM) in cloud environments (AWS, Azure, and GCP).

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* AWS - IAM

### Scripts

This playbook does not use any scripts.

### Commands

* aws-iam-get-user
* gcp-iam-service-accounts-get
* gsuite-user-get
* gcp-iam-service-account-keys-get
* gcp-iam-project-role-list
* gsuite-role-assignment-list
* aws-iam-list-user-policies
* aws-iam-list-groups-for-user
* msgraph-user-get
* msgraph-identity-protection-risky-user-history-list
* msgraph-groups-list-groups
* aws-iam-list-access-keys-for-user
* aws-iam-list-attached-user-policies

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| username | User name. |  | Optional |
| GCPProjectName | The GCP project name. |  | Optional |
| cloudProvider | The cloud service provider involved. |  | Optional |
| cloudIdentityType | The cloud identity type. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AWS.IAM.Users | AWS AM Users include:<br/>UserId<br/>Arn<br/>CreateDate<br/>Path<br/>PasswordLastUsed | unknown |
| AWS.IAM.Users.AccessKeys | AWS IAM Users Access Keys include:<br/>AccessKeyId<br/>Status<br/>CreateDate<br/>UserName | unknown |
| GCPIAM | GCP IAM information. | unknown |
| GSuite | GSuite user information. | unknown |
| GSuite.PageToken | Token to specify the next page in the list. | unknown |
| MSGraphUser | MSGraph user information. | unknown |
| MSGraphGroups | MSGraph groups information. | unknown |
| MSGraph.identityProtection | MSGraph identity protection - risky user history. | unknown |
| AWS.IAM.Users.AccessKeys.CreateDate | The date when the access key was created. | unknown |
| AWS.IAM.Users.AccessKeys.UserName | The name of the IAM user that the key is associated with. | unknown |
| AWS.IAM.Users.Groups | AWS IAM - User groups. | unknown |
| AWS.IAM.UserPolicies | AWS IAM - user inline policies. | unknown |
| AWS.IAM.AttachedUserPolicies | AWS IAM - User attached policies. | unknown |
| MSGraphGroup | MSGraph group information. | unknown |

## Playbook Image

---

![Cloud IAM Enrichment - Generic](../doc_files/Cloud_IAM_Enrichment_-_Generic.png)
