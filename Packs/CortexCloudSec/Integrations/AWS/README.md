Support for AWS cloud
This integration was integrated and tested with version 1.0.0 of Cortex CloudSec - AWS.

## Configure Cortex CloudSec - AWS in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Role Name | ARN of the role to be used for authentication | True |
| Role Session Name | Role session name to be used for authentication | True |
| Role Session Duration | Max role session duration | False |
| Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| PrivateLink service URL. |  | False |
| STS PrivateLink URL. |  | False |
| AWS STS Regional Endpoints | Sets the AWS_STS_REGIONAL_ENDPOINTS environment variable to specify the AWS STS endpoint resolution logic. By default, this option is set to “legacy” in AWS. Leave empty if the environment variable is already set using server configuration. | False |
| Role name for cross-organization account access | The role name used to access accounts in the organization. This role name must exist in the accounts provided in "AWS Organization accounts" and be assumable with the credentials provided. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-s3-public-access-block-update

***
Creates or modifies the PublicAccessBlock configuration for an Amazon S3 bucket.

#### Base Command

`aws-s3-public-access-block-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required | 
| region | The AWS region. | Required | 
| bucket | The name of the Amazon S3 bucket. | Required | 
| block_public_acls | Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket. Possible values are: true, false. | Optional | 
| ignore_public_acls | Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket. Possible values are: true, false. | Optional | 
| block_public_policy | Specifies whether Amazon S3 should block public bucket policies for this bucket. Possible values are: true, false. | Optional | 
| restrict_public_buckets | Specifies whether Amazon S3 should restrict public bucket policies for this bucket. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### aws-iam-account-password-policy-get

***
Get AWS account's password policy.

#### Base Command

`aws-iam-account-password-policy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.PasswordPolicy.MinimumPasswordLength | number | Minimum length to require for IAM user passwords. | 
| AWS.IAM.PasswordPolicy.RequireSymbols | boolean | Specifies whether IAM user passwords must contain at least one of the symbols. | 
| AWS.IAM.PasswordPolicy.RequireNumbers | boolean | Specifies whether IAM user passwords must contain at least one numeric character \(0 to 9\). | 
| AWS.IAM.PasswordPolicy.RequireUppercaseCharacters | boolean | Specifies whether IAM user passwords must contain at least one uppercase character \(A to Z\). | 
| AWS.IAM.PasswordPolicy.RequireLowercaseCharacters | boolean | Specifies whether IAM user passwords must contain at least one lowercase character \(a to z\). | 
| AWS.IAM.PasswordPolicy.AllowUsersToChangePassword | boolean | Specifies whether IAM users are allowed to change their own password. | 
| AWS.IAM.PasswordPolicy.ExpirePasswords | boolean | Indicates whether passwords in the account expire. | 
| AWS.IAM.PasswordPolicy.MaxPasswordAge | number | The number of days that an IAM user password is valid. | 
| AWS.IAM.PasswordPolicy.PasswordReusePrevention | number | Specifies the number of previous passwords that IAM users are prevented from reusing. | 
| AWS.IAM.PasswordPolicy.HardExpiry | boolean | Specifies whether IAM users are prevented from setting a new password via the Amazon Web Services Management Console after their password has expired. | 

### aws-ec2-instance-metadata-options-modify

***
Modify the EC2 instance metadata parameters on a running or stopped instance.

#### Base Command

`aws-ec2-instance-metadata-options-modify`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required | 
| region | The AWS region. | Required | 
| instance_id | The ID of the instance. | Required | 
| http_tokens | Indicates whether IMDSv2 is required. Possible values are: optional, required. | Optional | 
| http_endpoint | Enables or disables the HTTP metadata endpoint on your instances. Possible values are: disabled, enabled. | Optional | 

#### Context Output

There is no context output for this command.
### aws-iam-account-password-policy-update

***
Create/update password policy.

#### Base Command

`aws-iam-account-password-policy-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS account ID. | Required | 
| minimum_password_length | The minimum number of characters allowed in an IAM user password. Possible values are: . | Optional | 
| require_symbols | Specifies whether IAM user passwords must contain at least one of the non-alphanumeric characters. Can be "True" or "False". Possible values are: true, false. | Optional | 
| require_numbers | Specifies whether IAM user passwords must contain at least one numeric character (0 to 9). Can be "True" or "False". Possible values are: true, false. | Optional | 
| require_uppercase_characters | Specifies whether IAM user passwords must contain at least one uppercase character from the ISO basic Latin alphabet (A to Z). Can be "True" or "False". Possible values are: true, false. | Optional | 
| require_lowercase_characters | Specifies whether IAM user passwords must contain at least one lowercase character from the ISO basic Latin alphabet (a to z). Can be "True" or "False". Possible values are: true, false. | Optional | 
| allow_users_to_change_password | Allows all IAM users in your account to use the AWS Management Console to change their own passwords. Can be "True" or "False". Possible values are: true, false. | Optional | 
| max_password_age | The number of days that an IAM user password is valid. Possible values are: . | Optional | 
| password_reuse_prevention | Specifies the number of previous passwords that IAM users are prevented from reusing. Possible values are: . | Optional | 
| hard_expiry | Prevents IAM users from setting a new password after their password has expired. Can be "True" or "False". Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
