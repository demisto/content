Amazon Web Services Identity and Access Management Identity Center(IAM)

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

## Configure AWS - IAM Identity Center on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS - IAM Identity Center.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Role Arn |  | True |
    | Role Session Name |  | True |
    | AWS Default Region |  | True |
    | Role Session Duration |  | False |
    | Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
    | Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Identity Store ID |  | True |
    | Secret Key |  | True |
    | Access Key |  | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-iam-identitycenter-create-user

***
Creates a new IAM Identity Center user for your AWS account.

#### Base Command

`aws-iam-identitycenter-create-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The username of the user to create. | Required | 
| familyName | The family name of the user to create. | Optional | 
| givenName | The First name of the user to create. | Required | 
| userEmailAddress | The email address of the user to create. | Required | 
| displayName | The display name of the user to create. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.Users.UserId | date | The date and time, when the user was created. | 

### aws-iam-identitycenter-get-user

***
Retrieves information about the specified IAM user, including the user creation date, path, unique ID, and ARN.

#### Base Command

`aws-iam-identitycenter-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user to get information about. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.IdentityCenter.Users.UserName | string | The friendly name identifying the user. | 
| AWS.IAM.IdentityCenter.Users.UserId | string | The stable and unique string identifying the user. | 
| AWS.IAM.IdentityCenter.Users.Email | string | The user email address. | 
| AWS.IAM.IdentityCenter.Users.DisplayName | unknown | The user display name in AWS IAM IdentityCenter. | 

### aws-iam-identitycenter-list-users

***
Lists the IAM users, returns all users in the AWS account.

#### Base Command

`aws-iam-identitycenter-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.Users.UserName | string | The friendly name identifying the user. | 
| AWS.IAMIdentityCenter.Users.UserId | string | The stable and unique string identifying the user. | 

### aws-iam-identitycenter-list-groups

***
Lists all the IAM groups in the AWS account.

#### Base Command

`aws-iam-identitycenter-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.IdentityCenter.Groups.GroupName | string | The friendly name that identifies the group. | 
| AWS.IAM.IdentityCenter.Groups.GroupId | string | The stable and unique string identifying the group. | 

### aws-iam-identitycenter-list-groups-for-user

***
Lists the IAM groups that the specified IAM user belongs to.

#### Base Command

`aws-iam-identitycenter-list-groups-for-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user to list groups for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.IdentityCenter.Users.GroupMemeberships.GroupName | string | The friendly name that identifies the group. | 
| AWS.IAM.IdentityCenter.Users.GroupMemeberships.GroupId | string | The stable and unique string identifying the group. | 

### aws-iam-identitycenter-add-user-to-group

***
Adds the specified user to the specified group.

#### Base Command

`aws-iam-identitycenter-add-user-to-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user to add. | Required | 
| groupName | The name of the group to update. | Required | 

#### Context Output

There is no context output for this command.

### aws-iam-identitycenter-get-group

***
Get AWS IAM Identity Center group Information.

#### Base Command

`aws-iam-identitycenter-get-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | The name of the group to search. | Required | 

#### Context Output

There is no context output for this command.

### aws-iam-identitycenter-remove-user-from-all-groups

***
This will remove the entered user from all groups/memberships.

#### Base Command

`aws-iam-identitycenter-remove-user-from-all-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | Username that will be removed from all groups. | Required | 

#### Context Output

There is no context output for this command.

### aws-iam-identitycenter-get-user-by-email

***
This will get user information using email address.

#### Base Command

`aws-iam-identitycenter-get-user-by-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| emailAddress | The email of the user to be removed. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAM.IdentityCenter.Users.UserName | string | The friendly name identifying the user. | 
| AWS.IAM.IdentityCenter.Users.Email | string | The email address identifying the user. | 
| AWS.IAM.IdentityCenter.Users.UserId | string | The user ID of the queried user. | 
| AWS.IAM.IdentityCenter.Users.DisplayName | string | The display name of the queried user. | 
