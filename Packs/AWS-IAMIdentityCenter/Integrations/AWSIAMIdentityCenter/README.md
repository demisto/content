Amazon Web Services Identity and Access Management Identity Center(IAM)

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

## Configure AWS - IAM Identity Center in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Role Arn |  | False |
| Role Session Name | A descriptive name for the assumed role session. | False |
| AWS Default Region |  | True |
| Role Session Duration |  | False |
| Identity Store ID | The Identity Store ID parameter is required for API requests. It can be provided as a parameter or as an argument. If the Identity Store ID was not specified - Test failure. | False |
| Access Key |  | False |
| Secret Key |  | False |
| Access Key |  | False |
| Secret Key |  | False |
| Timeout | The time in seconds until a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 seconds will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| Trust any certificate (not secure) |  | False |



## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| familyName | The family name of the user to create. | Required | 
| givenName | The first name of the user to create. | Required | 
| userEmailAddress | The email address of the user to create. | Optional | 
| displayName | The display name of the user to create. | Required | 
| profileUrl | The profile URL of the user to create. | Optional | 
| userEmailAddressPrimary | Is this the primary email address for the associated resource?. Possible values are: yes, no. | Optional | 
| userType | The type of the user to create. | Optional | 
| title | The title of the user to create. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.User.UserId | string | The user ID. | 
| AWS.IAMIdentityCenter.User.IdentityStoreId | string | Identity Store ID. | 

#### Command example
```!aws-iam-identitycenter-create-user displayName="John Doe" familyName=Doe givenName=John userName=johndoe userEmailAddress=johnDoe@gmail.com```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "User": {
                "IdentityStoreId": "d-9967750fbd",
                "UserId": "634418e2-20c1-703e-4358-a8312472c85d"
            }
        }
    }
}
```

#### Human Readable Output

>### User johndoe has been successfully created with user id 634418e2-20c1-703e-4358-a8312472c85d
>|IdentityStoreId|UserId|
>|---|---|
>| d-9967750fbd | 634418e2-20c1-703e-4358-a8312472c85d |



### aws-iam-identitycenter-get-user

***
Retrieves information about the specified IAM user.

#### Base Command

`aws-iam-identitycenter-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| userName | The name of the user to get information about. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.User.UserName | string | The friendly name identifying the user. | 
| AWS.IAMIdentityCenter.User.UserId | string | The stable and unique string identifying the user. | 
| AWS.IAMIdentityCenter.User.ExternalIds.Issuer | String | The issuer for an external identifier. | 
| AWS.IAMIdentityCenter.User.ExternalIds.Id | String | The identifier issued to this resource by an external identity provider. | 
| AWS.IAMIdentityCenter.User.Name.Formatted | String | Formatted version of the user's name for display. | 
| AWS.IAMIdentityCenter.User.Name.FamilyName | String | The family name of the user. | 
| AWS.IAMIdentityCenter.User.Name.GivenName | String | The given name of the user. | 
| AWS.IAMIdentityCenter.User.Name.MiddleName | String | The middle name of the user. | 
| AWS.IAMIdentityCenter.User.Name.HonorificPrefix | String | The honorific prefix of the user. | 
| AWS.IAMIdentityCenter.User.Name.HonorificSuffix | String | The honorific suffix of the user. | 
| AWS.IAMIdentityCenter.User.DisplayName | String | The name of the user formatted for display when referenced. | 
| AWS.IAMIdentityCenter.User.NickName | String | An alternate name for the user. | 
| AWS.IAMIdentityCenter.User.ProfileUrl | String | URL associated with the user. | 
| AWS.IAMIdentityCenter.User.Emails.Value | String | Email address associated with the user. | 
| AWS.IAMIdentityCenter.User.Emails.Type | String | Type of email address. | 
| AWS.IAMIdentityCenter.User.Emails.Primary | String | Indicates whether this is the primary email address. | 
| AWS.IAMIdentityCenter.User.Addresses.StreetAddress | String | Street address. | 
| AWS.IAMIdentityCenter.User.Addresses.Locality | String | Address locality. | 
| AWS.IAMIdentityCenter.User.Addresses.Region | String | Region of the address. | 
| AWS.IAMIdentityCenter.User.Addresses.PostalCode | String | Postal code of the address. | 
| AWS.IAMIdentityCenter.User.Addresses.Country | String | Country of the address. | 
| AWS.IAMIdentityCenter.User.Addresses.Formatted | String | Formatted version of the address for display. | 
| AWS.IAMIdentityCenter.User.Addresses.Type | String | Type of address. | 
| AWS.IAMIdentityCenter.User.Addresses.Primary | String | Indicates whether this is the primary address. | 
| AWS.IAMIdentityCenter.User.PhoneNumbers.Value | String | Phone number associated with the user. | 
| AWS.IAMIdentityCenter.User.PhoneNumbers.Type | String | Type of phone number. | 
| AWS.IAMIdentityCenter.User.PhoneNumbers.Primary | String | Indicates whether this is the primary phone number. | 
| AWS.IAMIdentityCenter.User.UserType | String | Type of user. | 
| AWS.IAMIdentityCenter.User.Title | String | Title of the user. | 
| AWS.IAMIdentityCenter.User.PreferredLanguage | String | Preferred language of the user. | 
| AWS.IAMIdentityCenter.User.Locale | String | Geographical region or location of the user. | 
| AWS.IAMIdentityCenter.User.Timezone | String | Time zone of the user. | 
| AWS.IAMIdentityCenter.User.IdentityStoreId | String | Globally unique identifier for the identity store. | 

#### Command example
```!aws-iam-identitycenter-get-user userName=johndoe```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "User": {
                "DisplayName": "John Doe",
                "Emails": [
                    {
                        "Value": "johnDoe@gmail.com"
                    }
                ],
                "IdentityStoreId": "d-9967750fbd",
                "Name": {
                    "FamilyName": "Doe",
                    "GivenName": "John"
                },
                "UserId": "634418e2-20c1-703e-4358-a8312472c85d",
                "UserName": "johndoe"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS IAM Identity Center Users
>|DisplayName|Emails|UserId|UserName|
>|---|---|---|---|
>| John Doe | johnDoe@gmail.com | 634418e2-20c1-703e-4358-a8312472c85d | johndoe |



### aws-iam-identitycenter-list-users

***
Lists the IAM users, returns all users in the AWS account.

#### Base Command

`aws-iam-identitycenter-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| limit | Number of results to return. Default is 50. | Optional | 
| nextToken | The pagination token. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.User.UserName | string | The friendly name identifying the user. | 
| AWS.IAMIdentityCenter.User.UserId | string | The stable and unique string identifying the user. | 
| AWS.IAMIdentityCenter.User.ExternalIds.Issuer | String | The issuer for an external identifier. | 
| AWS.IAMIdentityCenter.User.ExternalIds.Id | String | The identifier issued to this resource by an external identity provider. | 
| AWS.IAMIdentityCenter.User.Name.Formatted | String | Formatted version of the user's name for display. | 
| AWS.IAMIdentityCenter.User.Name.FamilyName | String | The family name of the user. | 
| AWS.IAMIdentityCenter.User.Name.GivenName | String | The given name of the user. | 
| AWS.IAMIdentityCenter.User.Name.MiddleName | String | The middle name of the user. | 
| AWS.IAMIdentityCenter.User.Name.HonorificPrefix | String | The honorific prefix of the user. | 
| AWS.IAMIdentityCenter.User.Name.HonorificSuffix | String | The honorific suffix of the user. | 
| AWS.IAMIdentityCenter.User.DisplayName | String | The name of the user formatted for display when referenced. | 
| AWS.IAMIdentityCenter.User.NickName | String | An alternate name for the user. | 
| AWS.IAMIdentityCenter.User.ProfileUrl | String | URL associated with the user. | 
| AWS.IAMIdentityCenter.User.Emails.Value | String | Email address associated with the user. | 
| AWS.IAMIdentityCenter.User.Emails.Type | String | Type of email address. | 
| AWS.IAMIdentityCenter.User.Emails.Primary | String | Indicates whether this is the primary email address. | 
| AWS.IAMIdentityCenter.User.Addresses.StreetAddress | String | Street address. | 
| AWS.IAMIdentityCenter.User.Addresses.Locality | String | Address locality. | 
| AWS.IAMIdentityCenter.User.Addresses.Region | String | Region of the address. | 
| AWS.IAMIdentityCenter.User.Addresses.PostalCode | String | Postal code of the address. | 
| AWS.IAMIdentityCenter.User.Addresses.Country | String | Country of the address. | 
| AWS.IAMIdentityCenter.User.Addresses.Formatted | String | Formatted version of the address for display. | 
| AWS.IAMIdentityCenter.User.Addresses.Type | String | Type of address. | 
| AWS.IAMIdentityCenter.User.Addresses.Primary | String | Indicates whether this is the primary address. | 
| AWS.IAMIdentityCenter.User.PhoneNumbers.Value | String | Phone number associated with the user. | 
| AWS.IAMIdentityCenter.User.PhoneNumbers.Type | String | Type of phone number. | 
| AWS.IAMIdentityCenter.User.PhoneNumbers.Primary | String | Indicates whether this is the primary phone number. | 
| AWS.IAMIdentityCenter.User.UserType | String | Type of user. | 
| AWS.IAMIdentityCenter.User.Title | String | Title of the user. | 
| AWS.IAMIdentityCenter.User.PreferredLanguage | String | Preferred language of the user. | 
| AWS.IAMIdentityCenter.User.Locale | String | Geographical region or location of the user. | 
| AWS.IAMIdentityCenter.User.Timezone | String | Time zone of the user. | 
| AWS.IAMIdentityCenter.User.IdentityStoreId | String | Globally unique identifier for the identity store. | 
| AWS.IAMIdentityCenter.UserNextToken | String | Pagination token. | 

#### Command example
```!aws-iam-identitycenter-list-users```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "User": [
                {
                    "DisplayName": "John Doe",
                    "Emails": [
                        {
                            "Value": "johnDoe@gmail.com"
                        }
                    ],
                    "IdentityStoreId": "d-9967750fbd",
                    "Name": {
                        "FamilyName": "Doe",
                        "GivenName": "John"
                    },
                    "UserId": "8374c852-10e1-70e2-8996-5b0d54bf8ccd",
                    "UserName": "johndoe"
                },
            ],
            "UserNextToken": null
        }
    }
}
```

#### Human Readable Output

>### AWS IAM Identity Center Users
>|DisplayName|Emails|UserId|UserName|
>|---|---|---|---|
>| johndoe | johnDoe@gmail.com | 8374c852-10e1-70e2-8996-5b0d54bf8ccd | johndoe |



### aws-iam-identitycenter-list-groups

***
Lists all the IAM groups in the AWS account.

#### Base Command

`aws-iam-identitycenter-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| limit | Number of results to return. Default is 50. | Optional | 
| nextToken | The pagination token. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.Group.GroupId | String | The identifier for a group in the identity store. | 
| AWS.IAMIdentityCenter.Group.DisplayName | String | The display name value for the group. | 
| AWS.IAMIdentityCenter.Group.ExternalIds.Issuer | String | The issuer for an external identifier. | 
| AWS.IAMIdentityCenter.Group.ExternalIds.Id | String | The identifier issued to this resource by an external identity provider. | 
| AWS.IAMIdentityCenter.Group.Description | String | A description of the specified group. | 
| AWS.IAMIdentityCenter.Group.IdentityStoreId | String | The globally unique identifier for the identity store. | 
| AWS.IAMIdentityCenter.GroupNextToken | String | The pagination token used for the ListUsers and ListGroups API operations. | 

#### Command example
```!aws-iam-identitycenter-list-groups```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "Group": [
                {
                    "DisplayName": "new",
                    "GroupId": "53142802-e001-7004-9134-9e6e4e1e10c0",
                    "IdentityStoreId": "d-9967750fbd"
                }
            ],
            "GroupNextToken": null
        }
    }
}
```

#### Human Readable Output

>### AWS IAM Identity Center Groups
>|DisplayName|GroupId|
>|---|---|
>| new | 53142802-e001-7004-9134-9e6e4e1e10c0 |


### aws-iam-identitycenter-list-groups-for-user

***
Lists the IAM Identity Center groups that the specified IAM user belongs to.

#### Base Command

`aws-iam-identitycenter-list-groups-for-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| limit | Number of results to return. Default is 50. | Optional | 
| nextToken | The pagination token. | Optional | 
| userName | The name of the user to list groups for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.User.UserId | string | User ID. | 
| AWS.IAMIdentityCenter.User.GroupMemeberships.MembershipId | string | The friendly name that identifies the group. | 
| AWS.IAMIdentityCenter.User.GroupMemeberships.GroupId | string | The stable and unique string identifying the group. | 


#### Command example
```!aws-iam-identitycenter-list-groups-for-user userName=johndoe```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "GroupsUserNextToken":null,
            "User":{
                "GroupMemberships":[
                    {
                        "GroupId":"a3948882-5051-7090-524c-c8c850bf1919",
                        "MembershipId":"e374b872-9011-7000-c847-55fdcc299204",
                    }
                ],
                "UserId":"c3f438a2-e041-7033-75e8-63eb8c64b0e4"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS IAM Identity Center Groups
>|GroupID|MembershipID|UserID|
>|---|---|---|
>| a3948882-5051-7090-524c-c8c850bf1919 | e374b872-9011-7000-c847-55fdcc299204 | c3f438a2-e041-7033-75e8-63eb8c64b0e4 |


### aws-iam-identitycenter-add-user-to-group

***
Adds the specified user to the specified group.

#### Base Command

`aws-iam-identitycenter-add-user-to-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| userName | The name of the user to add. | Required | 
| groupName | The name of the group to update. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-iam-identitycenter-add-user-to-group groupName=NewGroup userName=johndoe```
#### Human Readable Output

>The membership id 4314c862-b0c1-705e-d5da-ccf59fd045f3 has been successfully created.

### aws-iam-identitycenter-get-group

***
Get AWS IAM Identity Center group Information.

#### Base Command

`aws-iam-identitycenter-get-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| displayName | The name of the group to search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.Group.GroupId | String | The identifier for a group in the identity store. | 
| AWS.IAMIdentityCenter.Group.DisplayName | String | The display name of the group. | 
| AWS.IAMIdentityCenter.Group.ExternalIds.Issuer | String | The issuer for an external identifier. | 
| AWS.IAMIdentityCenter.Group.ExternalIds.Id | String | The identifier issued to this resource by an external identity provider. | 
| AWS.IAMIdentityCenter.Group.Description | String | A description of the group. | 
| AWS.IAMIdentityCenter.Group.IdentityStoreId | String | The globally unique identifier for the identity store. | 

#### Command example
```!aws-iam-identitycenter-get-group displayName=NewGroup```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "Group": {
                "Description": "New",
                "DisplayName": "NewGroup",
                "GroupId": "f3a478d2-50b1-7078-81a4-c97c703007f3",
                "IdentityStoreId": "d-9967750fbd"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS IAM Identity Center Groups
>|DisplayName|GroupId|
>|---|---|
>| NewGroup | f3a478d2-50b1-7078-81a4-c97c703007f3 |


### aws-iam-identitycenter-get-user-by-email

***
Retrieves information about the specified IAM user.

#### Base Command

`aws-iam-identitycenter-get-user-by-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| emailAddress | The email of the user. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.User.UserName | string | The friendly name identifying the user. | 
| AWS.IAMIdentityCenter.User.UserId | string | The stable and unique string identifying the user. | 
| AWS.IAMIdentityCenter.User.ExternalIds.Issuer | String | The issuer for an external identifier. | 
| AWS.IAMIdentityCenter.User.ExternalIds.Id | String | The identifier issued to this resource by an external identity provider. | 
| AWS.IAMIdentityCenter.User.Name.Formatted | String | Formatted version of the user's name for display. | 
| AWS.IAMIdentityCenter.User.Name.FamilyName | String | The family name of the user. | 
| AWS.IAMIdentityCenter.User.Name.GivenName | String | The given name of the user. | 
| AWS.IAMIdentityCenter.User.Name.MiddleName | String | The middle name of the user. | 
| AWS.IAMIdentityCenter.User.Name.HonorificPrefix | String | The honorific prefix of the user. | 
| AWS.IAMIdentityCenter.User.Name.HonorificSuffix | String | The honorific suffix of the user. | 
| AWS.IAMIdentityCenter.User.DisplayName | String | The name of the user formatted for display when referenced. | 
| AWS.IAMIdentityCenter.User.NickName | String | An alternate name for the user. | 
| AWS.IAMIdentityCenter.User.ProfileUrl | String | URL associated with the user. | 
| AWS.IAMIdentityCenter.User.Emails.Value | String | Email address associated with the user. | 
| AWS.IAMIdentityCenter.User.Emails.Type | String | Type of email address. | 
| AWS.IAMIdentityCenter.User.Emails.Primary | String | Indicates whether this is the primary email address. | 
| AWS.IAMIdentityCenter.User.Addresses.StreetAddress | String | Street address. | 
| AWS.IAMIdentityCenter.User.Addresses.Locality | String | Address locality. | 
| AWS.IAMIdentityCenter.User.Addresses.Region | String | Region of the address. | 
| AWS.IAMIdentityCenter.User.Addresses.PostalCode | String | Postal code of the address. | 
| AWS.IAMIdentityCenter.User.Addresses.Country | String | Country of the address. | 
| AWS.IAMIdentityCenter.User.Addresses.Formatted | String | Formatted version of the address for display. | 
| AWS.IAMIdentityCenter.User.Addresses.Type | String | Type of address. | 
| AWS.IAMIdentityCenter.User.Addresses.Primary | String | Indicates whether this is the primary address. | 
| AWS.IAMIdentityCenter.User.PhoneNumbers.Value | String | Phone number associated with the user. | 
| AWS.IAMIdentityCenter.User.PhoneNumbers.Type | String | Type of phone number. | 
| AWS.IAMIdentityCenter.User.PhoneNumbers.Primary | String | Indicates whether this is the primary phone number. | 
| AWS.IAMIdentityCenter.User.UserType | String | Type of user. | 
| AWS.IAMIdentityCenter.User.Title | String | Title of the user. | 
| AWS.IAMIdentityCenter.User.PreferredLanguage | String | Preferred language of the user. | 
| AWS.IAMIdentityCenter.User.Locale | String | Geographical region or location of the user. | 
| AWS.IAMIdentityCenter.User.Timezone | String | Time zone of the user. | 
| AWS.IAMIdentityCenter.User.IdentityStoreId | String | Globally unique identifier for the identity store. | 


#### Command example
```!aws-iam-identitycenter-get-user-by-email emailAddress=johnDoe@gmail.com```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "User": {
                "DisplayName": "John Doe",
                "Emails": [
                    {
                        "Primary": true,
                        "Type": "work",
                        "Value": "johnDoe@gmail.com"
                    }
                ],
                "IdentityStoreId": "d-9967750fbd",
                "Name": {
                    "FamilyName": "Doe",
                    "GivenName": "John"
                },
                "UserId": "13746842-e011-70fe-14fe-600d496510f0",
                "UserName": "johndoe",
            }
        }
    }
}
```

#### Human Readable Output

>### AWS IAM Identity Center Users
>|DisplayName|Emails|UserId|UserName|
>|---|---|---|---|
>| John Doe | johnDoe@gmail.com | 13746842-e011-70fe-14fe-600d496510f0 | johndoe |

### aws-iam-identitycenter-list-memberships

***
Lists the memberships of the group.

#### Base Command

`aws-iam-identitycenter-list-memberships`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| limit | Number of results to return. Default is 50. | Optional | 
| nextToken | The pagination token. | Optional | 
| groupName | The name of the group to list the memberships. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.GroupMemberships.IdentityStoreId | String | The globally unique identifier for the identity store. | 
| AWS.IAMIdentityCenter.Group.GroupMemberships.MembershipId | String | The identifier for a GroupMembership object in an identity store. | 
| AWS.IAMIdentityCenter.Group.GroupId | String | The identifier for a group in the identity store. | 
| AWS.IAMIdentityCenter.Group.GroupMemberships.UserId | String | Identifier of resources that can be members. | 
| AWS.IAMIdentityCenter.GroupMembershipNextToken | String | The pagination token. | 


#### Command example
```!aws-iam-identitycenter-list-memberships groupName=NewGroup```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "Group": {
                "GroupMemberships":[
                    {
                        "MembershipId":"e374b872-9011-7000-c847-55fdcc299204",
                        "UserId":"c3f438a2-e041-7033-75e8-63eb8c64b0e4"
                    }
                ]
            },
            "GroupMembershipNextToken":null
        }
    }
}
```

#### Human Readable Output

>|GroupId|MembershipId|UserId|
>|---|---|
>| a3948882-5051-7090-524c-c8c850bf1919	 | e374b872-9011-7000-c847-55fdcc299204 | c3f438a2-e041-7033-75e8-63eb8c64b0e4 |


### aws-iam-identitycenter-delete-user

***
Removes the specified user from the AWS IAM Identity Center.

#### Base Command

`aws-iam-identitycenter-delete-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| userName | The name of the user to remove. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-iam-identitycenter-delete-user userName=johndoe```
#### Human Readable Output

>The User 634418e2-20c1-703e-4358-a8312472c85d has been removed.

### aws-iam-identitycenter-delete-group

***
Removes the specified group from the IAM Identity Center.

#### Base Command

`aws-iam-identitycenter-delete-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| groupName | The name of the group to remove. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-iam-identitycenter-delete-group groupName=NewGroup```
#### Human Readable Output

>The Group f3a478d2-50b1-7078-81a4-c97c703007f3 has been removed.

### aws-iam-identitycenter-create-group

***
Creates a new IAM Identity Center group for your AWS account.

#### Base Command

`aws-iam-identitycenter-create-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| displayName | The name of the group to create. | Required | 
| description | The description of the group to create. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.Group.GroupId | string | The user ID. | 
| AWS.IAMIdentityCenter.Group.IdentityStoreId | string | Identity store ID. | 

#### Command example
```!aws-iam-identitycenter-create-group description=New displayName=NewGroup```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "Group": {
                "GroupId": "f3a478d2-50b1-7078-81a4-c97c703007f3",
                "IdentityStoreId": "d-9967750fbd"
            }
        }
    }
}
```

#### Human Readable Output

>### Group NewGroup has been successfully created with id f3a478d2-50b1-7078-81a4-c97c703007f3
>|GroupId|IdentityStoreId|
>|---|---|
>| f3a478d2-50b1-7078-81a4-c97c703007f3 | d-9967750fbd |


### aws-iam-identitycenter-update-group

***
Updates an IAM Identity Center group for your AWS account.

#### Base Command

`aws-iam-identitycenter-update-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| displayName | The name of the group to update. | Required | 
| description | The description of the group to update. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-iam-identitycenter-update-group description=changed displayName=NewGroup```
#### Human Readable Output

>Group NewGroup has been successfully updated

### aws-iam-identitycenter-update-user

***
Updates an IAM Identity Center user for your AWS account.

#### Base Command

`aws-iam-identitycenter-update-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The username of the user to update. | Required | 
| familyName | The family name of the user to update. | Optional | 
| givenName | The first name of the user to update. | Optional | 
| userEmailAddressPrimary | Is this the primary email address for the associated resource. Possible values are: yes, no. | Optional | 
| userEmailAddress | The email address of the user to update. | Optional | 
| displayName | The display name of the user to update. | Optional | 
| profileUrl | The profile URL of the user to update. | Optional | 
| userType | The type of the user to update. | Optional | 
| title | The title of the user to update. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 

#### Context Output

There is no context output for this command.


#### Command example
```!aws-iam-identitycenter-update-user userName=johndoe familyName=changed```

#### Human Readable Output

>User johndoe has been successfully updated

### aws-iam-identitycenter-delete-group-membership

***
Deletes a user from all groups if a username is provided, or deletes multiple memberships if a list of memberships is provided.

#### Base Command

`aws-iam-identitycenter-delete-group-membership`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name. | Optional | 
| roleSessionDuration | Role session duration. | Optional | 
| roleSessionName | Role session name. | Optional | 
| IdentityStoreId | Identity store ID. | Optional | 
| userName | The name of the user to delete from all groups. | Optional | 
| membershipId | Comma-separated list of membership IDs to delete. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-iam-identitycenter-delete-group-membership userName=johndoe```
#### Human Readable Output

>User is not member of any group.