Update an AWS - EC2 instance with a list of accounts in an AWS organization, which will allow EC2 commands to run in all of them.
This script can be run on a schedule to keep an AWS - EC2 instance in sync with the created, deleted or removed accounts of the organization.

### Prerequisites
- An ***AWS - EC2*** instance.
- An ***AWS - Organizations*** instance with a working `aws-org-account-list` command.
- A ***Core REST API*** instance.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Amazon Web Services |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| ec2_instance_name | The name of the AWS - EC2 instance integration to update. |
| org_instance_name | The name of the AWS - Organizations instance to collect account from. If not provided, the primary instance will be used. |
| exclude_accounts | A comma-separated list of accounts to exclude. |
| max_accounts | The maximum number of accounts to retrieve. Default is 50. |

## Outputs

---
There are no outputs for this script.

## Script Examples

### Example command

```!AwsEC2SyncAccounts ec2_instance_name="AWS_EC2_Instance" org_instance_name="AWS_Organizations_Instance"```

### Human Readable Output

> ## Successfully updated ***AWS_EC2_Instance*** with accounts:
> ---  
>### AWS Organization Accounts
>|Id|Arn|Name|Email|JoinedMethod|JoinedTimestamp|Status|
>|---|---|---|---|---|---|---|
>| 111222333444 | arn:aws:organizations::111222333444:account/o-abcde12345/111222333444 | Name | user@xsoar.com | CREATED | 2023-09-04 09:17:14.299000+00:00 | ACTIVE |
>| 111222333444 | arn:aws:organizations::111222333444:account/o-abcde12345/111222333444 | John Doe | user@xsoar.com | INVITED | 2022-07-25 09:11:23.528000+00:00 | SUSPENDED |
