Amazon Web Services Identity and Access Management Identity Center(IAM)

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

## Configure AWS - IAM Identity Center on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS - IAM Identity Center - TEST.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Role Arn |  | False |
    | Role Session Name |  | False |
    | AWS Default Region |  | True |
    | Role Session Duration |  | False |
    | Identity Store ID |  | False |
    | Access Key |  | False |
    | Secret Key |  | False |
    | Access Key |  | False |
    | Secret Key |  | False |
    | Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
    | Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  |  |

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
| familyName | The family name of the user to create. | Required | 
| givenName | The First name of the user to create. | Required | 
| userEmailAddress | The email address of the user to create. | Optional | 
| displayName | The display name of the user to create. | Required | 
| profileUrl | The profile URL of the user to create. | Optional | 
| userEmailAddressPrimary | Is this the primary email address for the associated resource. Possible values are: yes, no. Default is True. | Optional | 
| userType | The type of the user to create. | Optional | 
| title | The title of the user to create. | Optional | 
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.User.UserId | string | The user Id. | 
| AWS.IAMIdentityCenter.User.IdentityStoreId | string | Identity Store Id. | 

#### Command example
```!aws-iam-identitycenter-create-user displayName=example familyName=fam givenName=example userName=exampleName userEmailAddress=test@example.com```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "User": {
                "IdentityStoreId": "d-9967750fbd",
                "UserId": "63849862-e011-704f-ebde-a0eb7208bbed"
            }
        }
    }
}
```

#### Human Readable Output

>### User 63849862-e011-704f-ebde-a0eb7208bbed has been successfully created
>|IdentityStoreId|UserId|
>|---|---|
>| d-9967750fbd | 63849862-e011-704f-ebde-a0eb7208bbed |



### aws-iam-identitycenter-get-user

***
Retrieves information about the specified IAM user, including the user creation date, path, unique ID, and ARN.

#### Base Command

`aws-iam-identitycenter-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
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
```!aws-iam-identitycenter-get-user userName=exampleName```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "User": {
                "Addresses": [
                    {
                        "Region": "None"
                    }
                ],
                "DisplayName": "example",
                "Emails": [
                    {
                        "Primary": true,
                        "Type": "work",
                        "Value": "test@example.com"
                    }
                ],
                "IdentityStoreId": "d-9967750fbd",
                "Name": {
                    "FamilyName": "fam",
                    "GivenName": "example"
                },
                "ProfileUrl": "None",
                "Title": "None",
                "UserId": "63849862-e011-704f-ebde-a0eb7208bbed",
                "UserName": "exampleName",
                "UserType": "None"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS IAM Identity Center Users
>|DisplayName|Emails|UserId|UserName|
>|---|---|---|---|
>| example | test@example.com | 63849862-e011-704f-ebde-a0eb7208bbed | exampleName |



### aws-iam-identitycenter-list-users

***
Lists the IAM users, returns all users in the AWS account.

#### Base Command

`aws-iam-identitycenter-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
| limit | Number of results to display. Default is 50. | Optional | 
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
                    "DisplayName": "demisto admin",
                    "Emails": [
                        {
                            "Primary": true,
                            "Type": "work",
                            "Value": "roman@ferrum-techs.com"
                        }
                    ],
                    "IdentityStoreId": "d-9967750fbd",
                    "Name": {
                        "FamilyName": "admin",
                        "GivenName": "demisto"
                    },
                    "UserId": "0394d8f2-6071-7082-97bf-6faaa5c65752",
                    "UserName": "demistoadmin"
                },
                {
                    "Addresses": [
                        {
                            "Region": "None"
                        }
                    ],
                    "DisplayName": "ho",
                    "IdentityStoreId": "d-9967750fbd",
                    "Name": {
                        "FamilyName": "hib",
                        "GivenName": "hhh"
                    },
                    "ProfileUrl": "None",
                    "Title": "None",
                    "UserId": "0364f8b2-60d1-70da-7841-be6b2f3f81e3",
                    "UserName": "hi",
                    "UserType": "None"
                },
                {
                    "Addresses": [
                        {
                            "Region": "None"
                        }
                    ],
                    "DisplayName": "no",
                    "IdentityStoreId": "d-9967750fbd",
                    "Name": {
                        "FamilyName": "no",
                        "GivenName": "no"
                    },
                    "ProfileUrl": "None",
                    "Title": "None",
                    "UserId": "73d438c2-6041-7051-3c34-925c16f7f3a2",
                    "UserName": "no",
                    "UserType": "None"
                },
                {
                    "Addresses": [
                        {
                            "Region": "None"
                        }
                    ],
                    "DisplayName": "men",
                    "IdentityStoreId": "d-9967750fbd",
                    "Name": {
                        "FamilyName": "men",
                        "GivenName": "men"
                    },
                    "ProfileUrl": "None",
                    "Title": "None",
                    "UserId": "03e44862-5091-7043-a305-9509aca42ee9",
                    "UserName": "men",
                    "UserType": "None"
                },
                {
                    "Addresses": [
                        {
                            "Region": "None"
                        }
                    ],
                    "DisplayName": "michal",
                    "Emails": [
                        {
                            "Primary": true,
                            "Type": "work",
                            "Value": "michal@gmail.com"
                        }
                    ],
                    "IdentityStoreId": "d-9967750fbd",
                    "Name": {
                        "FamilyName": "dag",
                        "GivenName": "mich"
                    },
                    "ProfileUrl": "None",
                    "Title": "None",
                    "UserId": "b3f49862-9061-7048-493e-810e2816c546",
                    "UserName": "michal",
                    "UserType": "None"
                },
                {
                    "Addresses": [
                        {
                            "Region": "None"
                        }
                    ],
                    "DisplayName": "inbal",
                    "IdentityStoreId": "d-9967750fbd",
                    "Name": {
                        "FamilyName": "apt",
                        "GivenName": "inbal"
                    },
                    "ProfileUrl": "None",
                    "Title": "None",
                    "UserId": "d3f4a822-c071-70ee-8f4a-c954715e1adf",
                    "UserName": "inbali",
                    "UserType": "None"
                },
                {
                    "Addresses": [
                        {
                            "Region": "None"
                        }
                    ],
                    "DisplayName": "inbal",
                    "Emails": [
                        {
                            "Primary": true,
                            "Type": "work",
                            "Value": "inb@fma"
                        }
                    ],
                    "IdentityStoreId": "d-9967750fbd",
                    "Name": {
                        "FamilyName": "apt",
                        "GivenName": "inbal"
                    },
                    "ProfileUrl": "None",
                    "Title": "None",
                    "UserId": "9394f882-20c1-7022-eb94-daf20345a352",
                    "UserName": "inbalapt",
                    "UserType": "None"
                },
                {
                    "DisplayName": "N D",
                    "Emails": [
                        {
                            "Primary": true,
                            "Type": "work",
                            "Value": "nat2@test.com"
                        }
                    ],
                    "IdentityStoreId": "d-9967750fbd",
                    "Name": {
                        "FamilyName": "D",
                        "GivenName": "N"
                    },
                    "UserId": "a3c44842-00f1-70d1-64d8-20b3cdb652c7",
                    "UserName": "nat2"
                },
                {
                    "DisplayName": "IAM Admin CRTX-101245",
                    "Emails": [
                        {
                            "Primary": true,
                            "Type": "work",
                            "Value": "tomer@ferrum-techs.com"
                        }
                    ],
                    "IdentityStoreId": "d-9967750fbd",
                    "Name": {
                        "FamilyName": "Admin CRTX-101245",
                        "GivenName": "IAM"
                    },
                    "UserId": "b3a4c842-d0b1-7012-c097-06fd11161d83",
                    "UserName": "IAM_Admin_CRTX-101245"
                }
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
>| demisto admin | roman@ferrum-techs.com | 0394d8f2-6071-7082-97bf-6faaa5c65752 | demistoadmin |
>| ho |  | 0364f8b2-60d1-70da-7841-be6b2f3f81e3 | hi |
>| no |  | 73d438c2-6041-7051-3c34-925c16f7f3a2 | no |
>| men |  | 03e44862-5091-7043-a305-9509aca42ee9 | men |
>| michal | michal@gmail.com | b3f49862-9061-7048-493e-810e2816c546 | michal |
>| inbal |  | d3f4a822-c071-70ee-8f4a-c954715e1adf | inbali |
>| inbal | inb@fma | 9394f882-20c1-7022-eb94-daf20345a352 | inbalapt |
>| N D | nat2@test.com | a3c44842-00f1-70d1-64d8-20b3cdb652c7 | nat2 |
>| IAM Admin CRTX-101245 | tomer@ferrum-techs.com | b3a4c842-d0b1-7012-c097-06fd11161d83 | IAM_Admin_CRTX-101245 |



### aws-iam-identitycenter-list-groups

***
Lists all the IAM groups in the AWS account.

#### Base Command

`aws-iam-identitycenter-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
| limit | Number of results to display. Default is 50. | Optional | 
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
                    "DisplayName": "InbalGrou",
                    "GroupId": "7314b8c2-5071-7016-328c-5d2df98c68e6",
                    "IdentityStoreId": "d-9967750fbd"
                },
                {
                    "DisplayName": "IAMAdmin",
                    "GroupId": "83f42872-5041-7057-245e-2b9dba8afddc",
                    "IdentityStoreId": "d-9967750fbd"
                },
                {
                    "DisplayName": "InbalGroup",
                    "GroupId": "433458b2-50d1-7069-b61d-21238462c5f6",
                    "IdentityStoreId": "d-9967750fbd"
                },
                {
                    "DisplayName": "Newww",
                    "GroupId": "93c4c862-f001-70d2-567c-2982486b8e97",
                    "IdentityStoreId": "d-9967750fbd"
                },
                {
                    "DisplayName": "NatGoup3",
                    "GroupId": "83942812-e0e1-7079-a82c-98bd193e99fa",
                    "IdentityStoreId": "d-9967750fbd"
                },
                {
                    "DisplayName": "CRTX-101245",
                    "GroupId": "83846842-90b1-70d3-62c7-42bd21607654",
                    "IdentityStoreId": "d-9967750fbd"
                },
                {
                    "DisplayName": "NatGroup",
                    "GroupId": "6324b8b2-f061-7003-45b0-bf53443049b4",
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
>| InbalGrou | 7314b8c2-5071-7016-328c-5d2df98c68e6 |
>| IAMAdmin | 83f42872-5041-7057-245e-2b9dba8afddc |
>| InbalGroup | 433458b2-50d1-7069-b61d-21238462c5f6 |
>| Newww | 93c4c862-f001-70d2-567c-2982486b8e97 |
>| NatGoup3 | 83942812-e0e1-7079-a82c-98bd193e99fa |
>| CRTX-101245 | 83846842-90b1-70d3-62c7-42bd21607654 |
>| NatGroup | 6324b8b2-f061-7003-45b0-bf53443049b4 |



### aws-iam-identitycenter-list-groups-for-user

***
Lists the IAM Identity Center groups that the specified IAM user belongs to.

#### Base Command

`aws-iam-identitycenter-list-groups-for-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
| limit | Number of results to display. Default is 50. | Optional | 
| nextToken | The pagination token. | Optional | 
| userName | The name of the user to list groups for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.User.UserId | string | User Id. | 
| AWS.IAMIdentityCenter.User.GroupMemeberships.MembershipId | string | The friendly name that identifies the group. | 
| AWS.IAMIdentityCenter.User.GroupMemeberships.GroupId | string | The stable and unique string identifying the group. | 


### aws-iam-identitycenter-add-user-to-group

***
Adds the specified user to the specified group.

#### Base Command

`aws-iam-identitycenter-add-user-to-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
| userName | The name of the user to add. | Required | 
| groupName | The name of the group to update. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-iam-identitycenter-add-user-to-group groupName=NewGroup userName=exampleName```
#### Human Readable Output

>The membership id 13440832-e031-7086-c06d-ee87f8e20383 has been successfully created.

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
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
| displayName | The name of the group to search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.GroupId | String | The identifier for a group in the identity store. | 
| AWS.IAMIdentityCenter.DisplayName | String | The display name of the group. | 
| AWS.IAMIdentityCenter.ExternalIds.Issuer | String | The issuer for an external identifier. | 
| AWS.IAMIdentityCenter.ExternalIds.Id | String | The identifier issued to this resource by an external identity provider. | 
| AWS.IAMIdentityCenter.Description | String | A description of the group. | 
| AWS.IAMIdentityCenter.IdentityStoreId | String | The globally unique identifier for the identity store. | 

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
                "GroupId": "b394c8f2-4041-70d9-a717-ed7afaa9d24b",
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
>| NewGroup | b394c8f2-4041-70d9-a717-ed7afaa9d24b |


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

#### Base Command

`aws-iam-identitycenter-get-user-by-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
| emailAddress | The email of the user to be removed. | Required | 

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

### aws-iam-identitycenter-delete-group-membership

***
Deletes a user from all groups if a username is provided, or deletes multiple memberships if a list of memberships is provided.

#### Base Command

`aws-iam-identitycenter-delete-group-membership`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
| userName | The name of the user to delete from all groups. | Optional | 
| membershipId | Comma seperated list of membership Ids to delete. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-iam-identitycenter-delete-group-membership userName=exampleName```
#### Human Readable Output

>User is not member of any group.

### aws-iam-identitycenter-create-group

***
Creates a new IAM Identity Center group for your AWS account.

#### Base Command

`aws-iam-identitycenter-create-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
| displayName | The name of the group to create. | Optional | 
| description | The description of the group to create. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.Group.GroupId | string | The user Id. | 
| AWS.IAMIdentityCenter.Group.IdentityStoreId | string | Identity Store Id. | 

#### Command example
```!aws-iam-identitycenter-create-group description=New displayName=NewGroup```
#### Context Example
```json
{
    "AWS": {
        "IAMIdentityCenter": {
            "Group": {
                "GroupId": "b394c8f2-4041-70d9-a717-ed7afaa9d24b",
                "IdentityStoreId": "d-9967750fbd"
            }
        }
    }
}
```

#### Human Readable Output

>### Group b394c8f2-4041-70d9-a717-ed7afaa9d24b has been successfully created
>|GroupId|IdentityStoreId|
>|---|---|
>| b394c8f2-4041-70d9-a717-ed7afaa9d24b | d-9967750fbd |


### aws-iam-identitycenter-delete-group

***
Removes the entered group.

#### Base Command

`aws-iam-identitycenter-delete-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
| groupName | The name of the group to remove. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-iam-identitycenter-delete-group groupName=NewGroup```
#### Human Readable Output

>The Group b394c8f2-4041-70d9-a717-ed7afaa9d24b has been removed.

### aws-iam-identitycenter-list-memberships

***
Lists the memberships of the group.

#### Base Command

`aws-iam-identitycenter-list-memberships`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
| limit | Number of results to display. Default is 50. | Optional | 
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

### aws-iam-identitycenter-delete-user

***
Removes the entered user.

#### Base Command

`aws-iam-identitycenter-delete-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | Role Arn. | Optional | 
| roleSessionDuration | Role Session Duration. | Optional | 
| roleSessionName | Role Session Name. | Optional | 
| IdentityStoreId | Identity Store ID. | Optional | 
| userName | The name of the user to remove. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-iam-identitycenter-delete-user userName=exampleName```
#### Human Readable Output

>The User 63849862-e011-704f-ebde-a0eb7208bbed has been removed.

