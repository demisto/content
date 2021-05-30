Amazon Web Services Identity and Access Management (IAM)

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).


## Configure AWS - IAM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS - IAM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | roleArn | Role Arn | False |
    | roleSessionName | Role Session Name | False |
    | defaultRegion | AWS Default Region | False |
    | sessionDuration | Role Session Duration | False |
    | access_key | Access Key | False |
    | secret_key | Secret Key | False |
    | timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
    | retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
    | insecure | Trust any certificate (not secure) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-iam-create-user
***
Creates a new IAM user for your AWS account.


#### Base Command

`aws-iam-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user to create. | Required | 
| path | The path for the user name. This parameter is optional. If it is not included, it defaults to a slash (/). | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Users.UserName | string | The friendly name identifying the user. | 
| AWS.IAM.Users.UserId | string | The stable and unique string identifying the user. | 
| AWS.IAM.Users.Arn | string | The Amazon Resource Name \(ARN\) that identifies the user. | 
| AWS.IAM.Users.CreateDate | date | The date and time, when the user was created. | 
| AWS.IAM.Users.Path | string | The path to the user. | 


#### Command Example
```!aws-iam-create-user userName=Test path=/testusers/```


### aws-iam-get-user
***
Retrieves information about the specified IAM user, including the user's creation date, path, unique ID, and ARN.


#### Base Command

`aws-iam-get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user to get information about. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Users.UserName | string | The friendly name identifying the user. | 
| AWS.IAM.Users.UserId | string | The stable and unique string identifying the user. | 
| AWS.IAM.Users.Arn | string | The Amazon Resource Name \(ARN\) that identifies the user. | 
| AWS.IAM.Users.CreateDate | date | The date and time when the user was created. | 
| AWS.IAM.Users.Path | string | The path to the user. | 
| AWS.IAM.Users.PasswordLastUsed | date | The date and time,  when the user's password was last used to sign in to an AWS website. | 


#### Command Example
``` !aws-iam-get-user userName=test```


### aws-iam-list-users
***
Lists the IAM users, returns all users in the AWS account.


#### Base Command

`aws-iam-list-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Users.UserName | string | The friendly name identifying the user. | 
| AWS.IAM.Users.UserId | string | The stable and unique string identifying the user. | 
| AWS.IAM.Users.Arn | string | The Amazon Resource Name \(ARN\) that identifies the user. | 
| AWS.IAM.Users.CreateDate | date | The date and time when the user was created. | 
| AWS.IAM.Users.Path | string | The path to the user. | 


#### Command Example
``` !aws-iam-list-users```




### aws-iam-update-user
***
Updates the name and/or the path of the specified IAM user.


#### Base Command

`aws-iam-update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oldUserName | Name of the user to update. | Required | 
| newUserName | New name for the user. Include this parameter only if you're changing the user's name. | Optional | 
| newPath | New path for the IAM user. Include this parameter only if you're changing the user's path. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-update-user oldUserName=test newUserName=NewUserName34 newPath=/iamtest/ ```




### aws-iam-delete-user
***
Deletes the specified IAM user. The user must not belong to any groups or have any access keys, signing certificates, or attached policies.


#### Base Command

`aws-iam-delete-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user to delete. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-delete-user userName=userName34 ```




### aws-iam-update-login-profile
***
Changes the password for the specified IAM user.


#### Base Command

`aws-iam-update-login-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user whose password you want to update. | Required | 
| newPassword | The new password for the specified IAM user. | Required | 
| passwordResetRequired | Allows this new password to be used only once by requiring the specified IAM user to set a new password on next sign-in. Possible values are: True, False. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-update-login-profile userName=userName34 newPassword=ArdVaEC@1#$F%g% passwordResetRequired=True raw-response=true```




### aws-iam-create-group
***
Creates a new iam group.


#### Base Command

`aws-iam-create-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | The name of the group to create. Do not include the path in this value. | Optional | 
| path | The path to the group. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Groups.GroupName | string | The friendly name that identifies the group. | 
| AWS.IAM.Groups.GroupId | string | The stable and unique string identifying the group. | 
| AWS.IAM.Groups.Arn | string | The Amazon Resource Name \(ARN\) specifying the group. | 
| AWS.IAM.Groups.CreateDate | date | The date and time when the group was created. | 
| AWS.IAM.Groups.Path | string | The path to the group. | 


#### Command Example
```!aws-iam-create-group groupName=test path=/testgroups/ ```




### aws-iam-list-groups
***
Lists all the IAM groups in the AWS account


#### Base Command

`aws-iam-list-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Groups.GroupName | string | The friendly name that identifies the group. | 
| AWS.IAM.Groups.GroupId | string | The stable and unique string identifying the group. | 
| AWS.IAM.Groups.Arn | string | The Amazon Resource Name \(ARN\) specifying the group. | 
| AWS.IAM.Groups.CreateDate | date | The date and time when the group was created. | 
| AWS.IAM.Groups.Path | string | The path to the group. | 


#### Command Example
``` !aws-iam-list-groups```




### aws-iam-list-groups-for-user
***
Lists the IAM groups that the specified IAM user belongs to.


#### Base Command

`aws-iam-list-groups-for-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user to list groups for. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Users.Groups.GroupName | string | The friendly name that identifies the group. | 
| AWS.IAM.Users.Groups.GroupId | string | The stable and unique string identifying the group | 
| AWS.IAM.Users.Groups.Arn | string | The Amazon Resource Name \(ARN\) specifying the group. | 
| AWS.IAM.Users.Groups.CreateDate | date | The date and time when the group was created. | 
| AWS.IAM.Users.Groups.Path | string | The path to the group. | 


#### Command Example
```aws-iam-list-groups-for-user userName=test ```




### aws-iam-add-user-to-group
***
Adds the specified user to the specified group.


#### Base Command

`aws-iam-add-user-to-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user to add. | Required | 
| groupName | The name of the group to update. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-add-user-to-group userName=userName34 groupName=test ```




### aws-iam-create-access-key
***
Creates a new AWS secret access key and corresponding AWS access key ID for the specified user. The default status for new keys is Active .


#### Base Command

`aws-iam-create-access-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the IAM user that the new key will belong to. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Users.AccessKeys.AccessKeyId | string | The ID for this access key. | 
| AWS.IAM.Users.AccessKeys.SecretAccessKey | string | The secret key used to sign requests. | 
| AWS.IAM.Users.AccessKeys.Status | string | The status of the access key. Active means that the key is valid for API calls, while Inactive means it is not. | 
| AWS.IAM.Users.AccessKeys.CreateDate | date | The date when the access key was created. | 


#### Command Example
```!aws-iam-create-access-key userName=userName34 ```




### aws-iam-update-access-key
***
Changes the status of the specified access key from Active to Inactive, or vice versa. This operation can be used to disable a user's key as part of a key rotation workflow.


#### Base Command

`aws-iam-update-access-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user whose key you want to update. | Required | 
| accessKeyId | The access key ID of the secret access key you want to update. | Required | 
| status | The status you want to assign to the secret access key. Active means that the key can be used for API calls to AWS, while Inactive means that the key cannot be used. Possible values are: Active, Inactive. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-update-access-key userName=test accessKeyId=AKIAJSFAUQ7EDFPN7Y2D2A status=Inactive```




### aws-iam-list-access-keys-for-user
***
Returns information about the access key IDs associated with the specified IAM user.


#### Base Command

`aws-iam-list-access-keys-for-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Users.AccessKeys.AccessKeyId | string | The ID for this access key. | 
| AWS.IAM.Users.AccessKeys.Status | string | The status of the access key. Active means the key is valid for API calls; Inactive means it is not. | 
| AWS.IAM.Users.AccessKeys.CreateDate | date | The date when the access key was created. | 
| AWS.IAM.Users.AccessKeys.UserName | string | The name of the IAM user that the key is associated with. | 


#### Command Example
```!aws-iam-list-access-keys-for-user userName=userName34 ```




### aws-iam-list-policies
***
Lists all the managed policies that are available in your AWS account, including your own customer-defined managed policies and all AWS managed policies.


#### Base Command

`aws-iam-list-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The scope to use for filtering the results. To list only AWS managed policies, set Scope to AWS. To list only the customer managed policies in your AWS account, set Scope to Local. Possible values are: All, AWS, Local. Default is All. | Optional | 
| onlyAttached | A flag to filter the results to only the attached policies.  When OnlyAttached is true , the returned list contains only the policies that are attached to an IAM user, group, or role. When OnlyAttached is false , or when the parameter is not included, all policies are returned. Possible values are: True, False. Default is False. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Policies.PolicyName | string | The friendly name \(not ARN\) identifying the policy. | 
| AWS.IAM.Policies.PolicyId | string | The stable and unique string identifying the policy. | 
| AWS.IAM.Policies.Arn | string | The Amazon Resource Name \(ARN\). | 
| AWS.IAM.Policies.Path | string | The path to the policy. | 
| AWS.IAM.Policies.DefaultVersionId | string | The identifier for the version of the policy that is set as the default version. | 
| AWS.IAM.Policies.IsAttachable | string | Specifies whether the policy can be attached to an IAM user, group, or role. | 
| AWS.IAM.Policies.CreateDate | date | when the policy was created. | 
| AWS.IAM.Policies.UpdateDate | date | when the policy was last updated. | 
| AWS.IAM.Policies.AttachmentCount | number | The number of entities \(users, groups, and roles\) that the policy is attached to. | 


#### Command Example
``` !aws-iam-list-policies scope=AWS onlyAttached=True```




### aws-iam-list-roles
***
Lists all IAM roles


#### Base Command

`aws-iam-list-roles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Roles.RoleName | string | The friendly name that identifies the role. | 
| AWS.IAM.Roles.RoleId | string | The stable and unique string identifying the role. | 
| AWS.IAM.Roles.Arn | string | The Amazon Resource Name \(ARN\) specifying the role. | 
| AWS.IAM.Roles.CreateDate | date | The date and time when the role was created. | 
| AWS.IAM.Roles.Path | string | The path to the role. | 
| AWS.IAM.Roles.AssumeRolePolicyDocument | string | The policy that grants an entity permission to assume the role. | 
| AWS.IAM.Roles.Description | string | A description of the role that you provide. | 
| AWS.IAM.Roles.MaxSessionDuration | number | The maximum session duration \(in seconds\) for the specified role. Anyone who uses the AWS CLI or API to assume the role can specify the duration using the optional DurationSeconds API parameter or duration-seconds CLI parameter. | 


#### Command Example
``` !aws-iam-list-roles```




### aws-iam-attach-policy
***
Attaches the specified managed policy to the specified IAM Entity.


#### Base Command

`aws-iam-attach-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The Type of IAM Entity. Possible values are: User, Group, Role. | Required | 
| entityName | The name (friendly name, not ARN) of the IAM Entity to attach the policy to. | Optional | 
| policyArn | The Amazon Resource Name (ARN) of the IAM policy you want to attach. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-attach-policy type=User entityName=userName34 policyArn=arn:aws:iam::aws:policy/AmazonSQSFullAccess```




### aws-iam-detach-policy
***
Removes the specified managed policy from the specified IAM Entity.


#### Base Command

`aws-iam-detach-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | IAM Entity Type. Possible values are: User, Group, Role. | Required | 
| entityName | The name (friendly name, not ARN) of the IAM Entity to detach the policy from. | Optional | 
| policyArn | The Amazon Resource Name (ARN) of the IAM policy you want to detach. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-detach-policy type=User entityName=userName34 policyArn=arn:aws:iam::aws:policy/AmazonSQSFullAccess ```




### aws-iam-delete-login-profile
***
Deletes the password for the specified IAM user, which terminates the user's ability to access AWS services through the AWS Management Console.


#### Base Command

`aws-iam-delete-login-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user whose password you want to delete. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-iam-delete-login-profile userName=userName34```




### aws-iam-delete-group
***
Deletes the specified IAM group. The group must not contain any users or have any attached policies.


#### Base Command

`aws-iam-delete-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | The name of the IAM group to delete. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-iam-delete-group groupName=Group123```




### aws-iam-remove-user-from-group
***
Removes the specified user from the specified group.


#### Base Command

`aws-iam-remove-user-from-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user to remove. | Required | 
| groupName | The name of the group to update. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-remove-user-from-group userName=userName34 groupName=Group123 ```




### aws-iam-create-login-profile
***
Creates a password for the specified user, giving the user the ability to access AWS services through the AWS Management Console.


#### Base Command

`aws-iam-create-login-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the IAM user to create a password for. The user must already exist. | Required | 
| password | The new password for the user. | Required | 
| passwordResetRequired | Specifies whether the user is required to set a new password on next sign-in. Possible values are: True, False. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-create-login-profile userName=userName34 password=Avd#sdf$12VB6*cvg passwordResetRequired=True ```




### aws-iam-delete-access-key
***
Deletes the access key pair associated with the specified IAM user.


#### Base Command

`aws-iam-delete-access-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | he name of the user whose access key pair you want to delete. | Required | 
| AccessKeyId | The access key ID for the access key ID and secret access key you want to delete. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-delete-access-key userName=userName34 AccessKeyId=ABCDEFGGHDJQ7E7X5PADN7Y2D2A ```




### aws-iam-create-instance-profile
***
Creates a new instance profile.


#### Base Command

`aws-iam-create-instance-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instanceProfileName | The name of the instance profile to create. | Required | 
| path | The path to the instance profile. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.InstanceProfiles.Path | string | The path to the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileName | string | The name identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileId | string | The stable and unique string identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.Arn | string | The Amazon Resource Name \(ARN\) specifying the instance profile. | 
| AWS.IAM.InstanceProfiles.CreateDate | date | The date when the instance profile was created. | 


#### Command Example
``` !aws-iam-create-instance-profile instanceProfileName=testprofile path=/test/```




### aws-iam-delete-instance-profile
***
Deletes the specified instance profile. The instance profile must not have an associated role.


#### Base Command

`aws-iam-delete-instance-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instanceProfileName | The name of the instance profile to delete. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-delete-instance-profile instanceProfileName=testprofile ```




### aws-iam-list-instance-profiles
***
Lists all the instance profiles tin your AWS account.


#### Base Command

`aws-iam-list-instance-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.InstanceProfiles.Path | string | The path to the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileName | string | The name identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileId | string | The stable and unique string identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.Arn | string | The Amazon Resource Name \(ARN\) specifying the instance profile. | 
| AWS.IAM.InstanceProfiles.CreateDate | date | The date when the instance profile was created. | 
| AWS.IAM.InstanceProfiles.Roles.Path | string | The path to the role. | 
| AWS.IAM.InstanceProfiles.Roles.RoleName | string | The friendly name that identifies the role. | 
| AWS.IAM.InstanceProfiles.Roles.RoleId | string | The stable and unique string identifying the role. | 
| AWS.IAM.InstanceProfiles.Roles.Arn | string | The Amazon Resource Name \(ARN\) specifying the role. | 
| AWS.IAM.InstanceProfiles.Roles.CreateDate | date | The date and time, when the role was created. | 
| AWS.IAM.InstanceProfiles.Roles.AssumeRolePolicyDocument | string | The policy that grants an entity permission to assume the role. | 
| AWS.IAM.InstanceProfiles.Roles.Description | string | A description of the role that you provide. | 
| AWS.IAM.InstanceProfiles.Roles.MaxSessionDuration | number | The maximum session duration \(in seconds\) for the specified role. | 


#### Command Example
``` !aws-iam-list-instance-profiles```




### aws-iam-add-role-to-instance-profile
***
Adds the specified IAM role to the specified instance profile. An instance profile can contain only one role, and this limit cannot be increased. You can remove the existing role and then add a different role to an instance profile.


#### Base Command

`aws-iam-add-role-to-instance-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instanceProfileName | The name of the instance profile to update. | Required | 
| roleName | The name of the role to add. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.InstanceProfiles.Path | string | The path to the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileName | string | The name identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileId | string | The stable and unique string identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.Arn | string | The Amazon Resource Name \(ARN\) specifying the instance profile. | 
| AWS.IAM.InstanceProfiles.CreateDate | date | The date when the instance profile was created. | 
| AWS.IAM.InstanceProfiles.Roles.Path | string | The path to the role. | 
| AWS.IAM.InstanceProfiles.Roles.RoleName | string | The friendly name that identifies the role. | 
| AWS.IAM.InstanceProfiles.Roles.RoleId | string | The stable and unique string identifying the role. | 
| AWS.IAM.InstanceProfiles.Roles.Arn | string | The Amazon Resource Name \(ARN\) specifying the role. | 
| AWS.IAM.InstanceProfiles.Roles.CreateDate | date | The date and time, when the role was created. | 
| AWS.IAM.InstanceProfiles.Roles.AssumeRolePolicyDocument | string | The policy that grants an entity permission to assume the role. | 
| AWS.IAM.InstanceProfiles.Roles.Description | string | A description of the role that you provide. | 
| AWS.IAM.InstanceProfiles.Roles.MaxSessionDuration | number | The maximum session duration \(in seconds\) for the specified role. | 


#### Command Example
``` !aws-iam-add-role-to-instance-profile instanceProfileName=testprofile roleName=EC2ReadOnly```




### aws-iam-remove-role-from-instance-profile
***
Removes the specified IAM role from the specified EC2 instance profile.


#### Base Command

`aws-iam-remove-role-from-instance-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instanceProfileName | The name of the instance profile to update. | Required | 
| roleName | The name of the role to remove. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.InstanceProfiles.Path | string | The path to the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileName | string | The name identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileId | string | The stable and unique string identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.Arn | string | The Amazon Resource Name \(ARN\) specifying the instance profile. | 
| AWS.IAM.InstanceProfiles.CreateDate | date | The date when the instance profile was created. | 
| AWS.IAM.InstanceProfiles.Roles.Path | string | The path to the role. | 
| AWS.IAM.InstanceProfiles.Roles.RoleName | string | The friendly name that identifies the role. | 
| AWS.IAM.InstanceProfiles.Roles.RoleId | string | The stable and unique string identifying the role. | 
| AWS.IAM.InstanceProfiles.Roles.Arn | string | The Amazon Resource Name \(ARN\) specifying the role. | 
| AWS.IAM.InstanceProfiles.Roles.CreateDate | date | The date and time, when the role was created. | 
| AWS.IAM.InstanceProfiles.Roles.AssumeRolePolicyDocument | string | The policy that grants an entity permission to assume the role. | 
| AWS.IAM.InstanceProfiles.Roles.Description | string | A description of the role that you provide. | 
| AWS.IAM.InstanceProfiles.Roles.MaxSessionDuration | number | The maximum session duration \(in seconds\) for the specified role. | 


#### Command Example
```!aws-iam-remove-role-from-instance-profile instanceProfileName=testprofile roleName=EC2ReadOnly ```




### aws-iam-list-instance-profiles-for-role
***
Lists the instance profiles that have the specified associated IAM role.


#### Base Command

`aws-iam-list-instance-profiles-for-role`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleName | The name of the role to list instance profiles for. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.InstanceProfiles.Path | string | The path to the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileName | string | The name identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileId | string | The stable and unique string identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.Arn | string | The Amazon Resource Name \(ARN\) specifying the instance profile. | 
| AWS.IAM.InstanceProfiles.CreateDate | date | The date when the instance profile was created. | 
| AWS.IAM.InstanceProfiles.Roles.Path | string | The path to the role. | 
| AWS.IAM.InstanceProfiles.Roles.RoleName | string | The friendly name that identifies the role. | 
| AWS.IAM.InstanceProfiles.Roles.RoleId | string | The stable and unique string identifying the role. | 
| AWS.IAM.InstanceProfiles.Roles.Arn | string | The Amazon Resource Name \(ARN\) specifying the role. | 
| AWS.IAM.InstanceProfiles.Roles.CreateDate | date | The date and time, when the role was created. | 
| AWS.IAM.InstanceProfiles.Roles.AssumeRolePolicyDocument | string | The policy that grants an entity permission to assume the role. | 
| AWS.IAM.InstanceProfiles.Roles.Description | string | A description of the role that you provide. | 
| AWS.IAM.InstanceProfiles.Roles.MaxSessionDuration | number | The maximum session duration \(in seconds\) for the specified role. | 


#### Command Example
``` !aws-iam-list-instance-profiles-for-role roleName=EC2ReadOnly```




### aws-iam-get-instance-profile
***
Retrieves information about the specified instance profile.


#### Base Command

`aws-iam-get-instance-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instanceProfileName | The name of the instance profile to get information about. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.InstanceProfiles.Path | string | The path to the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileName | string | The name identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.InstanceProfileId | string | The stable and unique string identifying the instance profile. | 
| AWS.IAM.InstanceProfiles.Arn | string | The Amazon Resource Name \(ARN\) specifying the instance profile. | 
| AWS.IAM.InstanceProfiles.CreateDate | date | The date when the instance profile was created. | 
| AWS.IAM.InstanceProfiles.Roles.Path | string | The path to the role. | 
| AWS.IAM.InstanceProfiles.Roles.RoleName | string | The friendly name that identifies the role. | 
| AWS.IAM.InstanceProfiles.Roles.RoleId | string | The stable and unique string identifying the role. | 
| AWS.IAM.InstanceProfiles.Roles.Arn | string | The Amazon Resource Name \(ARN\) specifying the role. | 
| AWS.IAM.InstanceProfiles.Roles.CreateDate | date | The date and time, when the role was created. | 
| AWS.IAM.InstanceProfiles.Roles.AssumeRolePolicyDocument | string | The policy that grants an entity permission to assume the role. | 
| AWS.IAM.InstanceProfiles.Roles.Description | string | A description of the role that you provide. | 
| AWS.IAM.InstanceProfiles.Roles. MaxSessionDuration | number | The maximum session duration \(in seconds\) for the specified role. | 


#### Command Example
```!aws-iam-get-instance-profile instanceProfileName=testprofile ```




### aws-iam-get-role
***
Retrieves information about the specified role.


#### Base Command

`aws-iam-get-role`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleName | The name of the IAM role to get information about. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Roles.Path | string | The path to the role. | 
| AWS.IAM.Roles.RoleName | string | The friendly name that identifies the role. | 
| AWS.IAM.Roles.RoleId | string | The stable and unique string identifying the role. | 
| AWS.IAM.Roles.Arn | string | The Amazon Resource Name \(ARN\) specifying the role. | 
| AWS.IAM.Roles.CreateDate | date | The date and time, when the role was created. | 
| AWS.IAM.Roles.AssumeRolePolicyDocument | string | The policy that grants an entity permission to assume the role. | 
| AWS.IAM.Roles.Description | string | A description of the role that you provide. | 
| AWS.IAM.Roles.MaxSessionDuration | number | The maximum session duration \(in seconds\) for the specified role. | 


#### Command Example
```!aws-iam-get-role roleName=ec2readonly ```




### aws-iam-delete-role
***
Deletes the specified role. The role must not have any policies attached. 


#### Base Command

`aws-iam-delete-role`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleName | The name of the role to delete. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-iam-delete-role roleName=test-role```




### aws-iam-create-role
***
Creates a new role for your AWS account.


#### Base Command

`aws-iam-create-role`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleName | The name of the role to create. | Required | 
| assumeRolePolicyDocument | The trust relationship policy document that grants an entity permission to assume the role. | Required | 
| path | The path to the role. | Optional | 
| description | A description of the role. | Optional | 
| maxSessionDuration | The maximum session duration (in seconds) that you want to set for the specified role. If you do not specify a value for this setting, the default maximum of one hour is applied. This setting can have a value from 1 hour to 12 hours. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Roles.RoleName | string | The friendly name that identifies the role. | 
| AWS.IAM.Roles.RoleId | string | The stable and unique string identifying the role. | 
| AWS.IAM.Roles.Arn | string | The Amazon Resource Name \(ARN\) specifying the role. | 
| AWS.IAM.Roles.CreateDate | date | The date and time, when the role was created. | 
| AWS.IAM.Roles.Path | string | The path to the role. | 
| AWS.IAM.Roles.AssumeRolePolicyDocument | string | he policy that grants an entity permission to assume the role. | 
| AWS.IAM.Roles.Description | string | A description of the role that you provide. | 
| AWS.IAM.Roles.MaxSessionDuration | number | The maximum session duration \(in seconds\) for the specified role. | 


#### Command Example
``` 
    !aws-iam-create-role roleName=testrole assumeRolePolicyDocument="{
    "Version": "2012-10-17",
    "Statement": [
    {
    "Effect": "Allow",
    "Principal": {
    "Service": "ec2.amazonaws.com"
    },
    "Action": "sts:AssumeRole"
    }
    ]
    }" description="a test role"
  ```


### aws-iam-create-policy
***
Creates a new managed policy for your AWS account.  This operation creates a policy version with a version identifier of v1 and sets v1 as the policy's default version.


#### Base Command

`aws-iam-create-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyName | The friendly name of the policy. | Required | 
| policyDocument | The JSON policy document that you want to use as the content for the new policy. | Required | 
| path | The path for the policy. | Optional | 
| description | A friendly description of the policy. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Policies.PolicyName | string | The friendly name \(not ARN\) identifying the policy. | 
| AWS.IAM.Policies.PolicyId | string | The stable and unique string identifying the policy. | 
| AWS.IAM.Policies.Arn | string | The Amazon Resource Name \(ARN\). ARNs are unique identifiers for AWS resources. | 
| AWS.IAM.Policies.Path | string | The path to the policy. | 
| AWS.IAM.Policies.DefaultVersionId | string | The identifier for the version of the policy that is set as the default version. | 
| AWS.IAM.Policies.AttachmentCount | number | The number of entities \(users, groups, and roles\) that the policy is attached to. | 
| AWS.IAM.Policies.PermissionsBoundaryUsageCount  | number | The number of entities \(users and roles\) for which the policy is used to set the permissions boundary. | 
| AWS.IAM.Policies.IsAttachable | boolean | Specifies whether the policy can be attached to an IAM user, group, or role. | 
| AWS.IAM.Policies.Description | string | A friendly description of the policy. | 
| AWS.IAM.Policies.CreateDate | date | The date and time, in ISO 8601 date-time format , when the policy was created. | 
| AWS.IAM.Policies.UpdateDate | date | The date and time, in ISO 8601 date-time format , when the policy was last updated. | 


#### Command Example
```
!aws-iam-create-policy policyName=test-policy policyDocument="{  
"Version": "2012-10-17",  
"Statement": \[  
{  
"Sid": "VisualEditor0",  
"Effect": "Allow",  
"Action": "guardduty:CreateIPSet",  
"Resource": "arn:aws:guardduty:_:_:detector/_"  
},  
{  
"Sid": "VisualEditor1",  
"Effect": "Allow",  
"Action": "guardduty:CreateDetector",  
"Resource": "_"  
}  
\]  
}"
 ```



### aws-iam-delete-policy
***
Deletes the specified managed policy.  Before you can delete a managed policy, you must first detach the policy from all users, groups, and roles that it is attached to. In addition you must delete all the policy's versions.


#### Base Command

`aws-iam-delete-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyArn | The Amazon Resource Name (ARN) of the IAM policy you want to delete. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-iam-delete-policy policyArn=arn:aws:iam::123456789:policy/test-policy```




### aws-iam-create-policy-version
***
Creates a new version of the specified managed policy. To update a managed policy, you create a new policy version. A managed policy can have up to five versions. If the policy has five versions, you must delete an existing version using DeletePolicyVersion before you create a new version.  Optionally, you can set the new version as the policy's default version. The default version is the version that is in effect for the IAM users, groups, and roles to which the policy is attached.


#### Base Command

`aws-iam-create-policy-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyArn | The Amazon Resource Name (ARN) of the IAM policy to which you want to add a new version. | Required | 
| policyDocument | The JSON policy document that you want to use as the content for this new version of the policy. | Required | 
| setAsDefault | Specifies whether to set this version as the policy's default version. Possible values are: True, False. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Policies.Versions.Document | string | The policy document. | 
| AWS.IAM.Policies.Versions.VersionId | string | The identifier for the policy version. | 
| AWS.IAM.Policies.Versions.IsDefaultVersion | string | The identifier for the policy version. | 
| AWS.IAM.Policies.Versions.CreateDate | string | The date and time, in ISO 8601 date-time format , when the policy version was created. | 


#### Command Example
``` 
!aws-iam-create-policy-version policyArn=arn:aws:iam::123456789:policy/test-policy policyDocument="{  
"Version": "2012-10-17",  
"Statement": \[  
{  
"Sid": "VisualEditor0",  
"Effect": "Allow",  
"Action": "guardduty:CreateIPSet",  
"Resource": "arn:aws:guardduty:_:_:detector/_"  
},  
{  
"Sid": "VisualEditor1",  
"Effect": "Allow",  
"Action": "guardduty:CreateDetector",  
"Resource": "_"  
}  
\]  
}" setAsDefault=True
```




### aws-iam-delete-policy-version
***
Deletes the specified version from the specified managed policy.  You cannot delete the default version from a policy using this API. To delete the default version from a policy, use DeletePolicy . To find out which version of a policy is marked as the default version, use ListPolicyVersions .


#### Base Command

`aws-iam-delete-policy-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyArn | The Amazon Resource Name (ARN) of the IAM policy from which you want to delete a version. | Required | 
| versionId | The policy version to delete. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-iam-delete-policy-version policyArn=arn:aws:iam::123456789:policy/test-policy versionId=v1 ```




### aws-iam-list-policy-versions
***
Lists information about the versions of the specified managed policy, including the version that is currently set as the policy's default version.


#### Base Command

`aws-iam-list-policy-versions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyArn | The Amazon Resource Name (ARN) of the IAM policy for which you want the versions. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Policies.Versions.Document | string | The policy document. | 
| AWS.IAM.Policies.Versions.VersionId | string | The identifier for the policy version. | 
| AWS.IAM.Policies.Versions.IsDefaultVersion | boolean | Specifies whether the policy version is set as the policy's default version. | 
| AWS.IAM.Policies.Versions.CreateDate | date | The date and time, in ISO 8601 date-time format , when the policy version was created. | 


#### Command Example
```!aws-iam-list-policy-versions policyArn=arn:aws:iam::123456789:policy/test-policy ```




### aws-iam-get-policy-version
***
Retrieves information about the specified version of the specified managed policy, including the policy document.


#### Base Command

`aws-iam-get-policy-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyArn | The Amazon Resource Name (ARN) of the managed policy that you want information about. | Required | 
| versionId | Identifies the policy version to retrieve. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.Policies.Versions.Document | unknown | The policy document. | 
| AWS.IAM.Policies.Versions.VersionId | unknown | The identifier for the policy version. | 
| AWS.IAM.Policies.Versions.IsDefaultVersion | unknown | Specifies whether the policy version is set as the policy's default version. | 
| AWS.IAM.Policies.Versions.CreateDate | unknown | The date and time, in ISO 8601 date-time format , when the policy version was created. | 


#### Command Example
```!aws-iam-get-policy-version policyArn=arn:aws:iam::123456789:policy/test-policy versionId=v3 ```




### aws-iam-set-default-policy-version
***
Sets the specified version of the specified policy as the policy's default (operative) version.  This operation affects all users, groups, and roles that the policy is attached to.


#### Base Command

`aws-iam-set-default-policy-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyArn | The Amazon Resource Name (ARN) of the IAM policy whose default version you want to set. | Required | 
| versionId | The version of the policy to set as the default (operative) version. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-iam-set-default-policy-version policyArn=arn:aws:iam::123456789:policy/test-policy versionId=v2```




### aws-iam-create-account-alias
***
Creates an alias for your AWS account.


#### Base Command

`aws-iam-create-account-alias`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| accountAlias | The account alias to create. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-iam-create-account-alias accountAlias=test-alias```




### aws-iam-delete-account-alias
***
Deletes the specified AWS account alias.


#### Base Command

`aws-iam-delete-account-alias`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| accountAlias | The name of the account alias to delete. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-iam-delete-account-alias accountAlias=demisto-test-alias```




### aws-iam-get-account-password-policy
***
Get AWS account's password policy


#### Base Command

`aws-iam-get-account-password-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.PasswordPolicy | Unknown | Account's password policy. | 


### aws-iam-update-account-password-policy
***
Create/update password policy


#### Base Command

`aws-iam-update-account-password-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| minimumPasswordLength | The minimum number of characters allowed in an IAM user password. Possible values are: . | Optional | 
| requireSymbols | Specifies whether IAM user passwords must contain at least one of the non-alphanumeric characters. Can be "True" or "False". Possible values are: True, False. | Optional | 
| requireNumbers | Specifies whether IAM user passwords must contain at least one numeric character (0 to 9). Can be "True" or "False". Possible values are: True, False. | Optional | 
| requireUppercaseCharacters | Specifies whether IAM user passwords must contain at least one uppercase character from the ISO basic Latin alphabet (A to Z). Can be "True" or "False". Possible values are: True, False. | Optional | 
| requireLowercaseCharacters | Specifies whether IAM user passwords must contain at least one lowercase character from the ISO basic Latin alphabet (a to z). Can be "True" or "False". Possible values are: True, False. | Optional | 
| allowUsersToChangePassword | Allows all IAM users in your account to use the AWS Management Console to change their own passwords. Can be "True" or "False". Possible values are: True, False. | Optional | 
| maxPasswordAge | The number of days that an IAM user password is valid. Possible values are: . | Optional | 
| passwordReusePrevention | Specifies the number of previous passwords that IAM users are prevented from reusing. Possible values are: . | Optional | 
| hardExpiry | Prevents IAM users from setting a new password after their password has expired. Can be "True" or "False". Possible values are: True, False. | Optional | 


#### Context Output

There is no context output for this command.


