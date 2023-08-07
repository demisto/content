This playbook performs an investigation on a specific user in AWS environments, using queries and logs from AWS CloudTrail.


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* AWS - CloudTrail

### Scripts

* LoadJSON
* GetTime
* Set

### Commands

* aws-cloudtrail-lookup-events

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Username | The username to investigate. |  | Optional |
| AwsTimeSearchFrom | The Search Time for the \`GetTime\` task used by the Aws Cloud Trail search query. <br/>This value represents the number of days to include in the search.<br/>Default value: 1.  \(1 Day\) | 1 | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AwsMFAConfigCount | Count of MFA config performed by the user in the AWS environment. | unknown |
| AwsUserRoleChnagesCount | Count of the user roles that were changed by the user in the AWS environment. | unknown |
| AwsSuspiciousActivitiesCount | Count of the suspicious activities performed by the user in the AWS environment. | unknown |
| AwsScriptBasedUserAgentCount | Count of Script-based user agent usages by the user in the AWS environment. | unknown |
| AwsAccessKeyActivitiesCount | Count of access key activities performed by the user in the AWS environment. | unknown |
| AwsSecurityChangesCount | Count of the security rules that were changed by the user in the AWS environment. | unknown |
| AwsAdminActivitiesCount | Count of administrative activities performed by the user in the AWS environment. | unknown |
| AwsApiAccessDeniedCount | Count of Api access denied by the user in the AWS environment. | unknown |
| AwsFailedLogonCount | Count of failed logins by the user in the AWS environment. | unknown |

## Playbook Image

---

![AWS - User Investigation](../doc_files/AWS_-_User_Investigation.png)
