Manage Amazon Web Services accounts and their resources.

## Configure AWS-Organizations on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS-Organizations.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Role Arn | The Amazon Resource Name (ARN) of the role to assume. | False | 
    | Role Session Name | An identifier for the assumed role session. | False | 
    | Role Session Duration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | False | 
    | Access Key |  | False |
    | Secret Key |  | False |
    | Timeout | The time in seconds until a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 seconds will be used. | False |
    | Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-org-root-list

***
List the roots that are defined in the current organization.

#### Base Command

`aws-org-root-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of roots to return. Default is 50. | Optional | 
| page_size | The number of roots to return per page. The maximum is 1000. | Optional | 
| next_token | The token denoting the next page of roots, as given by the response of the previous run of this command under the context key "AWS.Organizations.RootNextToken". | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.Root.Id | String | The unique identifier \(ID\) of the root. | 
| AWS.Organizations.Root.Arn | String | The Amazon Resource Name \(ARN\) of the root. | 
| AWS.Organizations.Root.Name | String | The friendly name of the root. | 
| AWS.Organizations.Root.PolicyTypes.Type | String | The name of the policy type. | 
| AWS.Organizations.Root.PolicyTypes.Status | String | The status of the policy type as it relates to the associated root. | 
| AWS.Organizations.RootNextToken | String | If not null, indicates that more output is available than is included in the current response. Use this value in the next_token argument in a subsequent call of the command to get the next part of the output. | 

#### Command example
```!aws-org-root-list```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "Root": {
                "Arn": "arn:aws:organizations::111222333444:root/o-abcde12345/r-ab12",
                "Id": "r-ab12",
                "Name": "Root",
                "PolicyTypes": [
                    {
                        "Status": "ENABLED",
                        "Type": "BACKUP_POLICY"
                    },
                    {
                        "Status": "ENABLED",
                        "Type": "SERVICE_CONTROL_POLICY"
                    }
                ]
            },
            "RootNextToken": null
        }
    }
}
```

#### Human Readable Output

>### AWS Organization Roots
>|Arn|Id|Name|
>|---|---|---|
>| arn:aws:organizations::111222333444:root/o-abcde12345/r-ab12 | r-ab12 | Root |


### aws-org-children-list

***
List all of the organizational units (OUs) or accounts that are contained in the specified parent OU or root.

#### Base Command

`aws-org-children-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent_id | The unique identifier (ID) for the parent root or organizational unit whose children are to be listed. | Required | 
| child_type | Filters the output to include only the specified child type. Possible values are: Account, OrganizationalUnit. | Required | 
| limit | The number of children to return. Default is 50. | Optional | 
| page_size | The number of children to return per page. The maximum is 1000. | Optional | 
| next_token | The token denoting the next page of children as given by the response of the previous run of this command under the context key "AWS.Organizations.ChildrenNextToken". | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.Children.Id | String | The unique identifier \(ID\) of the child entity. | 
| AWS.Organizations.Children.Type | String | The type of the child entity. | 
| AWS.Organizations.Children.ParentId | String | The unique identifier \(ID\) for the parent root or organizational unit of the child entity. | 
| AWS.Organizations.ChildrenNextToken | String | If not null, indicates that more output is available than is included in the current response. Use this value in the next_token argument in a subsequent call of the command to get the next part of the output. | 

#### Command example
```!aws-org-children-list parent_id="r-ab12" child_type="OrganizationalUnit"```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "Children": {
                "Id": "ou-ab12-abcd1234",
                "ParentId": "r-ab12",
                "Type": "ORGANIZATIONAL_UNIT"
            },
            "ChildrenNextToken": null
        }
    }
}
```

#### Human Readable Output

>### AWS Account *r-ab12* Children
>|Id|Type|
>|---|---|
>| ou-ab12-abcd1234 | ORGANIZATIONAL_UNIT |


### aws-org-parent-list

***
Lists all of the organizational units (OUs) or accounts that are a parent OU or root of the specified child.
This command returns only the immediate parents in the hierarchy.


#### Base Command

`aws-org-parent-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| child_id | The unique identifier (ID) of the organizational unit or account whose parent containers you want to list. Don't specify a root.<br/>This value can be retrieved by running the command "aws-org-account-list". | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.Parent.Id | String | The unique identifier \(ID\) of the parent entity. | 
| AWS.Organizations.Parent.Type | String | The type of the parent entity. | 
| AWS.Organizations.Parent.ChildId | String | The unique identifier \(ID\) of the organizational unit or account of the child of the parent entity. | 

#### Command example
```!aws-org-parent-list child_id="ou-ab12-abcd1234"```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "Parent": {
                "ChildId": "ou-ab12-abcd1234",
                "Id": "r-ab12",
                "Type": "ROOT"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Account *ou-ab12-abcd1234* Parent
>|Id|Type|
>|---|---|
>| r-ab12 | ROOT |


### aws-org-organization-unit-get

***
Retrieve information about an organizational unit (OU).
This command can be called only from the organization's management account or by a member account that is a delegated administrator for an Amazon Web Services service.


#### Base Command

`aws-org-organization-unit-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_unit_id | The unique identifier (ID) of the organizational unit to retrieve details about. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.OrganizationalUnit.Id | String | The unique identifier \(ID\) associated with the organizational unit. | 
| AWS.Organizations.OrganizationalUnit.Arn | String | The Amazon Resource Name \(ARN\) of the organizational unit. | 
| AWS.Organizations.OrganizationalUnit.Name | String | The friendly name of the organizational unit. | 

#### Command example
```!aws-org-organization-unit-get organization_unit_id="ou-ab12-abcd1234"```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "OrganizationalUnit": {
                "Arn": "arn:aws:organizations::111222333444:ou/o-abcde12345/ou-ab12-abcd1234",
                "Id": "ou-ab12-abcd1234",
                "Name": "Moishy OU"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Organization Unit
>|Arn|Id|Name|
>|---|---|---|
>| arn:aws:organizations::111222333444:ou/o-abcde12345/ou-ab12-abcd1234 | ou-ab12-abcd1234 | Moishy OU |


### aws-org-account-list

***
Lists all the accounts in the organization or a specific account by ID.

#### Base Command

`aws-org-account-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Get a specific account by ID. | Optional | 
| limit | The number of accounts to return. Default is 50. | Optional | 
| page_size | The number of accounts to return per page. The maximum is 1000. | Optional | 
| next_token | The token denoting the next page of accounts, as given by the response of the previous run of this command under the context key "AWS.Organizations.AccountNextToken". | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.Account.Id | String | The unique identifier \(ID\) of the account. | 
| AWS.Organizations.Account.Arn | String | The Amazon Resource Name \(ARN\) of the account. | 
| AWS.Organizations.Account.Email | String | The email address associated with the Amazon Web Services account. | 
| AWS.Organizations.Account.Name | String | The friendly name of the account. | 
| AWS.Organizations.Account.Status | String | The status of the account in the organization. | 
| AWS.Organizations.Account.JoinedMethod | String | The method by which the account joined the organization. | 
| AWS.Organizations.Account.JoinedTimestamp | Date | The date the account became a part of the organization. | 
| AWS.Organizations.AccountNextToken | String | If not null, indicates that more output is available than is included in the current response. Use this value in the next_token argument in a subsequent call of the command to get the next part of the output. | 

#### Command example
```!aws-org-account-list account_id=111222333444```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "Account": {
                "Arn": "arn:aws:organizations::111222333444:account/o-abcde12345/111222333444",
                "Email": "user@xsoar.com",
                "Id": "111222333444",
                "JoinedMethod": "CREATED",
                "JoinedTimestamp": "2023-09-04 09:17:14.299000+00:00",
                "Name": "Moishy",
                "Status": "ACTIVE"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Organization Accounts
>|Id|Arn|Name|Email|JoinedMethod|JoinedTimestamp|Status|
>|---|---|---|---|---|---|---|
>| 111222333444 | arn:aws:organizations::111222333444:account/o-abcde12345/111222333444 | Moishy | user@xsoar.com | CREATED | 2023-09-04 09:17:14.299000+00:00 | ACTIVE |


#### Command example
```!aws-org-account-list```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "Account": [
                {
                    "Arn": "arn:aws:organizations::111222333444:account/o-abcde12345/111222333444",
                    "Email": "user@xsoar.com",
                    "Id": "111222333444",
                    "JoinedMethod": "CREATED",
                    "JoinedTimestamp": "2023-09-04 09:17:14.299000+00:00",
                    "Name": "Moishy",
                    "Status": "ACTIVE"
                },
                {
                    "Arn": "arn:aws:organizations::111222333444:account/o-abcde12345/111222333444",
                    "Email": "user@xsoar.com",
                    "Id": "111222333444",
                    "JoinedMethod": "INVITED",
                    "JoinedTimestamp": "2022-07-25 09:11:23.528000+00:00",
                    "Name": "ferrum-techs",
                    "Status": "SUSPENDED"
                }
            ],
            "AccountNextToken": null
        }
    }
}
```

#### Human Readable Output

>### AWS Organization Accounts
>|Id|Arn|Name|Email|JoinedMethod|JoinedTimestamp|Status|
>|---|---|---|---|---|---|---|
>| 111222333444 | arn:aws:organizations::111222333444:account/o-abcde12345/111222333444 | Moishy | user@xsoar.com | CREATED | 2023-09-04 09:17:14.299000+00:00 | ACTIVE |
>| 111222333444 | arn:aws:organizations::111222333444:account/o-abcde12345/111222333444 | ferrum-techs | user@xsoar.com | INVITED | 2022-07-25 09:11:23.528000+00:00 | SUSPENDED |


### aws-org-organization-get

***
Retrieves information about the organization that the user's account belongs to.

#### Base Command

`aws-org-organization-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.Organization.Id | String | The unique identifier \(ID\) of the organization. | 
| AWS.Organizations.Organization.Arn | String | The Amazon Resource Name \(ARN\) of the organization. | 
| AWS.Organizations.Organization.FeatureSet | String | Specifies the functionality that currently is available to the organization. If set to “ALL”, then all features are enabled and policies can be applied to accounts in the organization. If set to “CONSOLIDATED_BILLING”, then only consolidated billing functionality is available. | 
| AWS.Organizations.Organization.MasterAccountArn | String | The Amazon Resource Name \(ARN\) of the account that is designated as the management account for the organization. | 
| AWS.Organizations.Organization.MasterAccountId | String | The unique identifier \(ID\) of the management account of the organization. | 
| AWS.Organizations.Organization.MasterAccountEmail | String | The email address that is associated with the Amazon Web Services account that is designated as the management account for the organization. | 

#### Command example
```!aws-org-organization-get```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "Organization": {
                "Arn": "arn:aws:organizations::111222333444:organization/o-abcde12345",
                "AvailablePolicyTypes": [
                    {
                        "Status": "ENABLED",
                        "Type": "SERVICE_CONTROL_POLICY"
                    }
                ],
                "FeatureSet": "ALL",
                "Id": "o-abcde12345",
                "MasterAccountArn": "arn:aws:organizations::111222333444:account/o-abcde12345/111222333444",
                "MasterAccountEmail": "user@xsoar.com",
                "MasterAccountId": "111222333444"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Organization
>|Id|Arn|FeatureSet|MasterAccountArn|MasterAccountId|MasterAccountEmail|
>|---|---|---|---|---|---|
>| o-abcde12345 | arn:aws:organizations::111222333444:organization/o-abcde12345 | ALL | arn:aws:organizations::111222333444:account/o-abcde12345/111222333444 | 111222333444 | user@xsoar.com |

