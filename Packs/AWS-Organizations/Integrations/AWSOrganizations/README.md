Manage Amazon Web Services accounts and their resources.
For AWS Organizations quotas, guidelines and restrictions, see the [AWS Organizations Quotas](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html) page.

## Configure AWS - Organizations in Cortex


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


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
>|Id|Arn|Name|
>|---|---|---|
>| r-ab12 | arn:aws:organizations::111222333444:root/o-abcde12345/r-ab12 | Root |


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
| AWS.Organizations.OrganizationUnit.Id | String | The unique identifier \(ID\) associated with the organizational unit. | 
| AWS.Organizations.OrganizationUnit.Arn | String | The Amazon Resource Name \(ARN\) of the organizational unit. | 
| AWS.Organizations.OrganizationUnit.Name | String | The friendly name of the organizational unit. | 

#### Command example
```!aws-org-organization-unit-get organization_unit_id=ou-ab12-abcd1234```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "OrganizationUnit": {
                "Arn": "arn:aws:organizations::111222333444:ou/o-abcde12345/ou-ab12-abcd1234",
                "Id": "ou-ab12-abcd1234",
                "Name": "Name OU"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Organization Unit
>|Id|Arn|Name|
>|---|---|---|
>| ou-ab12-abcd1234 | arn:aws:organizations::111222333444:ou/o-abcde12345/ou-ab12-abcd1234 | Name OU |


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
                "Name": "Name",
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
>| 111222333444 | arn:aws:organizations::111222333444:account/o-abcde12345/111222333444 | Name | user@xsoar.com | CREATED | 2023-09-04 09:17:14.299000+00:00 | ACTIVE |


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
                    "Name": "Name",
                    "Status": "ACTIVE"
                },
                {
                    "Arn": "arn:aws:organizations::111222333444:account/o-abcde12345/111222333444",
                    "Email": "user@xsoar.com",
                    "Id": "111222333444",
                    "JoinedMethod": "INVITED",
                    "JoinedTimestamp": "2022-07-25 09:11:23.528000+00:00",
                    "Name": "John Doe",
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
>| 111222333444 | arn:aws:organizations::111222333444:account/o-abcde12345/111222333444 | Name | user@xsoar.com | CREATED | 2023-09-04 09:17:14.299000+00:00 | ACTIVE |
>| 111222333444 | arn:aws:organizations::111222333444:account/o-abcde12345/111222333444 | john-doe | user@xsoar.com | INVITED | 2022-07-25 09:11:23.528000+00:00 | SUSPENDED |


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

### aws-org-organization-unit-create

***
Creates an organizational unit (OU) within a root or parent OU. An OU is a container for accounts that enables the organization of accounts to apply policies according to business requirements. The number of levels deep that OUs can be nested is dependent upon the policy types enabled for that root. For service control policies, the limit is five.

#### Base Command

`aws-org-organization-unit-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The friendly name to assign to the new organizational unit. | Required | 
| parent_id | The unique identifier (ID) of the parent root or organizational unit to create the new organizational unit in. This value can be retrieved by running the command "aws-org-root-list". | Required | 
| tags | A comma-separated list of tags to attach to the newly created organizational unit. Each tag should be in the format: "key=value". | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.OrganizationUnit.Id | String | The unique identifier \(ID\) associated with this organizational unit. | 
| AWS.Organizations.OrganizationUnit.Arn | String | The Amazon Resource Name \(ARN\) of this organizational unit. | 
| AWS.Organizations.OrganizationUnit.Name | String | The friendly name of this organizational unit. | 

#### Command example
```!aws-org-organization-unit-create name=test parent_id=r-12ab tags="new=true,key=value"```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "OrganizationUnit": {
                "Arn": "arn:aws:organizations::111222333444:ou/o-abcde12345/ou-ab12-abcd1234",
                "Id": "ou-ab12-abcd1234",
                "Name": "test"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Organization Unit
>|Id|Name|Arn|
>|---|---|---|
>| ou-ab12-abcd1234 | test | arn:aws:organizations::111222333444:ou/o-abcde12345/ou-ab12-abcd1234 |

### aws-org-organization-unit-rename

***
Renames the specified organizational unit (OU). The ID and ARN don’t change. The child OUs and accounts remain in place, and any attached policies of the OU remain attached.

#### Base Command

`aws-org-organization-unit-rename`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizational_unit_id | The unique identifier (ID) of the OU to rename. This value can be retrieved by running the command "aws-org-parent-list". | Required | 
| name | The new name to assign to the organizational unit. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-org-organization-unit-rename name=new_name organizational_unit_id=ou-ab12-abcd1234```

#### Human Readable Output

>AWS organization unit *ou-ab12-abcd1234* successfully renamed to *new_name*.

### aws-org-organization-unit-delete

***
Deletes an organizational unit (OU) from a root or another OU. All accounts and child OUs must first be removed.

#### Base Command

`aws-org-organization-unit-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizational_unit_id | The unique identifier (ID) of the organizational unit that you want to delete. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-org-organization-unit-delete organizational_unit_id=ou-ab12-abcd1234```

#### Human Readable Output

>AWS organizational unit *ou-ab12-abcd1234* deleted successfully.

### aws-org-policy-list

***
Retrieves the list of all policies in an organization of a specified type.

#### Base Command

`aws-org-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_type | Specifies the type of policy to include in the response. Possible values are: Service Control Policy, Tag Policy, Backup Policy, AI Services Opt Out Policy. | Required | 
| limit | The number of policies to return. Default is 50. | Optional | 
| page_size | The number of policies to return per page. The maximum is 1000. | Optional | 
| next_token | The token denoting the next page of policies, as given by the response of the previous run of this command under the context key "AWS.Organizations.PolicyNextToken". | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.Policy.Id | String | The unique identifier \(ID\) of the policy. | 
| AWS.Organizations.Policy.Arn | String | The Amazon Resource Name \(ARN\) of the policy. | 
| AWS.Organizations.Policy.Name | String | The friendly name of the policy. | 
| AWS.Organizations.Policy.Description | String | The description of the policy. | 
| AWS.Organizations.Policy.Type | String | The type of policy. | 
| AWS.Organizations.Policy.AwsManaged | Boolean | Indicates whether the specified policy is an Amazon Web Services managed policy. If true, the policy can be attached to roots, organizational units, or accounts, but cannot be edited. | 
| AWS.Organizations.PolicyNextToken | String | If not null, indicates that more output is available than is included in the current response. Use this value as the next_token argument in a subsequent call of the command to get the next part of the output. | 

#### Command example
```!aws-org-policy-list policy_type="Service Control Policy"```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "Policy": [
                {
                    "Arn": "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess",
                    "AwsManaged": true,
                    "Description": "Allows access to every operation",
                    "Id": "p-FullAWSAccess",
                    "Name": "FullAWSAccess",
                    "Type": "SERVICE_CONTROL_POLICY"
                },
                {
                    "Arn": "arn:aws:organizations::111222333444:policy/o-abcde12345/service_control_policy/p-1234abcd",
                    "AwsManaged": false,
                    "Description": "Used for test purposes",
                    "Id": "p-1234abcd",
                    "Name": "Test",
                    "Type": "SERVICE_CONTROL_POLICY"
                }
            ],
            "PolicyNextToken": null
        }
    }
}
```

#### Human Readable Output

>### AWS Organization Policies
>|Id|Arn|Name|Description|Type|AwsManaged|
>|---|---|---|---|---|---|
>| p-FullAWSAccess | arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess | FullAWSAccess | Allows access to every operation | SERVICE_CONTROL_POLICY | true |
>| p-1234abcd | arn:aws:organizations::111222333444:policy/o-abcde12345/service_control_policy/p-1234abcd | Test | Used for test purposes | SERVICE_CONTROL_POLICY | false |

### aws-org-policy-get

***
Retrieves information about a policy.

#### Base Command

`aws-org-policy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The unique identifier (ID) of the policy that you want details about. This value can be retrieved by running the command "aws-org-policy-list". | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.Policy.Id | String | The unique identifier \(ID\) of the policy. | 
| AWS.Organizations.Policy.Arn | String | The Amazon Resource Name \(ARN\) of the policy. | 
| AWS.Organizations.Policy.Name | String | The friendly name of the policy. | 
| AWS.Organizations.Policy.Description | String | The description of the policy. | 
| AWS.Organizations.Policy.Type | String | The type of policy. | 
| AWS.Organizations.Policy.AwsManaged | Boolean | Indicates whether the specified policy is an Amazon Web Services managed policy. If true, the policy can be attached to roots, organizational units, or accounts, but cannot be edited. | 

#### Command example
```!aws-org-policy-get policy_id=p-1234abcd```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "Policy": {
                "Arn": "arn:aws:organizations::111222333444:policy/o-abcde12345/service_control_policy/p-1234abcd",
                "AwsManaged": false,
                "Description": "Used for test purposes",
                "Id": "p-1234abcd",
                "Name": "Test",
                "Type": "SERVICE_CONTROL_POLICY"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Organization Policies
>|Id|Arn|Name|Description|Type|AwsManaged|
>|---|---|---|---|---|---|
>| p-1234abcd | arn:aws:organizations::111222333444:policy/o-abcde12345/service_control_policy/p-1234abcd | Test | Used for test purposes | SERVICE_CONTROL_POLICY | false |

### aws-org-policy-attach

***
Attaches a policy to a root, an organizational unit (OU), or an individual account.

#### Base Command

`aws-org-policy-attach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The unique identifier (ID) of the policy to attach to the target. This value can be retrieved by running the command "aws-org-policy-list". | Required | 
| target_id | The unique identifier (ID) of the root, organizational unit, or account to attach the policy to. This value can be retrieved by running the command "aws-org-root-list" or "aws-org-account-list". | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-org-policy-attach policy_id=p-1234abcd target_id=ou-ab12-abcd1234```

#### Human Readable Output

>AWS Organizations policy *p-1234abcd* successfully attached.

### aws-org-policy-target-list

***
Lists all the roots, organizational units (OUs), and accounts that the specified policy is attached to.

#### Base Command

`aws-org-policy-target-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The unique identifier (ID) of the policy whose attachments are to be listed. | Required | 
| limit | The number of policies to return. Default is 50. | Optional | 
| page_size | The number of policies to return per page. The maximum is 1000. | Optional | 
| next_token | The token denoting the next page of policies, as given by the response of the previous run of this command under the context key "AWS.Organizations.PolicyTargetNextToken". | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.PolicyTarget.TargetId | String | The unique identifier \(ID\) of the policy target. | 
| AWS.Organizations.PolicyTarget.Arn | String | The Amazon Resource Name \(ARN\) of the policy target. | 
| AWS.Organizations.PolicyTarget.Name | String | The friendly name of the policy target. | 
| AWS.Organizations.PolicyTarget.Type | String | The type of the policy target. | 
| AWS.Organizations.PolicyTarget.PolicyId | String | The unique identifier \(ID\) of the policy. | 
| AWS.Organizations.PolicyTargetNextToken | String | If not null, indicates that more output is available than is included in the current response. Use this value as the next_token argument in a subsequent call of the command to get the next part of the output. | 

#### Command example
```!aws-org-policy-target-list policy_id=p-1234abcd```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "PolicyTarget": {
                "Arn": "arn:aws:organizations::111222333444:ou/o-abcde12345/ou-ab12-abcd1234",
                "Name": "to_add_policy",
                "PolicyId": "p-1234abcd",
                "TargetId": "ou-ab12-abcd1234",
                "Type": "ORGANIZATIONAL_UNIT"
            },
            "PolicyTargetNextToken": null
        }
    }
}
```

#### Human Readable Output

>### AWS Organization *p-1234abcd* Targets
>|TargetId|Arn|Name|Type|
>|---|---|---|---|
>| ou-ab12-abcd1234 | arn:aws:organizations::111222333444:ou/o-abcde12345/ou-ab12-abcd1234 | to_add_policy | ORGANIZATIONAL_UNIT |

### aws-org-target-policy-list

***
Lists the policies that are directly attached to the specified target root, organizational unit (OU), or account.

#### Base Command

`aws-org-target-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_type | The type of policy to include in the returned list. Possible values are: Service Control Policy, Tag Policy, Backup Policy, AI Services Opt Out Policy. | Required | 
| target_id | The unique identifier (ID) of the root, organizational unit, or account whose policies are to be listed. | Required | 
| limit | The number of policies to return. Default is 50. | Optional | 
| page_size | The number of policies to return per page. The maximum is 1000. | Optional | 
| next_token | The token denoting the next page of policies, as given by the response of the previous run of this command under the context key "AWS.Organizations.PolicyNextToken". | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.TargetPolicy.Id | String | The unique identifier \(ID\) of the policy. | 
| AWS.Organizations.TargetPolicy.Arn | String | The Amazon Resource Name \(ARN\) of the policy. | 
| AWS.Organizations.TargetPolicy.Name | String | The friendly name of the policy. | 
| AWS.Organizations.TargetPolicy.Description | String | The description of the policy. | 
| AWS.Organizations.TargetPolicy.Type | String | The type of policy. | 
| AWS.Organizations.TargetPolicy.AwsManaged | Boolean | Indicates whether the specified policy is an Amazon Web Services managed policy. If true, the policy can be attached to roots, organizational units, or accounts, but cannot be edited. | 
| AWS.Organizations.TargetId | String | The unique identifier \(ID\) of the target. | 
| AWS.Organizations.TargetPolicyNextToken | String | If not null, indicates that more output is available than is included in the current response. Use this value as the next_token argument in a subsequent call of the command to get the next part of the output. | 

#### Command example
```!aws-org-target-policy-list target_id=ou-ab12-abcd1234 policy_type="Service Control Policy"```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "TargetPolicy": [
                {
                    "Arn": "arn:aws:organizations::111222333444:policy/o-abcde12345/service_control_policy/p-1234abcd",
                    "AwsManaged": false,
                    "Description": "Used for test purposes",
                    "Id": "p-1234abcd",
                    "Name": "Test",
                    "TargetId": "ou-ab12-abcd1234",
                    "Type": "SERVICE_CONTROL_POLICY"
                },
                {
                    "Arn": "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess",
                    "AwsManaged": true,
                    "Description": "Allows access to every operation",
                    "Id": "p-FullAWSAccess",
                    "Name": "FullAWSAccess",
                    "TargetId": "ou-ab12-abcd1234",
                    "Type": "SERVICE_CONTROL_POLICY"
                }
            ],
            "TargetPolicyNextToken": null
        }
    }
}
```

#### Human Readable Output

>### AWS Organization *ou-ab12-abcd1234* Policies
>|Id|Arn|Name|Description|Type|AwsManaged|
>|---|---|---|---|---|---|
>| p-1234abcd | arn:aws:organizations::111222333444:policy/o-abcde12345/service_control_policy/p-1234abcd | Test | Used for test purposes | SERVICE_CONTROL_POLICY | false |
>| p-FullAWSAccess | arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess | FullAWSAccess | Allows access to every operation | SERVICE_CONTROL_POLICY | true |

### aws-org-policy-delete

***
Deletes the specified policy from the organization. Before performing this operation, the policy must be detached from all organizational units (OUs), roots, and accounts.

#### Base Command

`aws-org-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The unique identifier (ID) of the policy that you want to delete. This value can be retrieved by running the command "aws-org-policy-list". | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-org-policy-delete policy_id=p-1234abcd```

#### Human Readable Output

>AWS Organizations policy *p-1234abcd* successfully deleted.

### aws-org-resource-tag-add

***
Adds one or more tags to the specified resource.

#### Base Command

`aws-org-resource-tag-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | The ID of the resource to add a tag to. This value can be retrieved by running the command "aws-org-root-list", "aws-org-account-list", "aws-org-root-list", or "aws-org-policy-list". | Required | 
| tags | A comma-separated list of tags to attach to the resource. Each tag should be in the format: "key=value". | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-org-resource-tag-add resource_id=ou-ab12-abcd1234 tags="test=true,key=value"```


#### Human Readable Output

>AWS Organizations resource *ou-ab12-abcd1234* successfully tagged.

### aws-org-resource-tag-list

***
Lists tags that are attached to the specified resource.

#### Base Command

`aws-org-resource-tag-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | The ID of the resource with the tags to list. This value can be retrieved by running the command "aws-org-root-list", "aws-org-account-list", "aws-org-root-list", or "aws-org-policy-list". | Required | 
| next_token | The token denoting the next page of tags, as given by the response of the previous run of this command under the context key "AWS.Organizations.TagNextToken". | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Organizations.Tag.Key | String | The key identifier, or name, of the tag. | 
| AWS.Organizations.Tag.Value | String | The string value that's associated with the key of the tag. | 
| AWS.Organizations.Tag.ResourceId | String | The unique identifier \(ID\) of the resource. | 
| AWS.Organizations.TagNextToken | String | If not null, indicates that more output is available than is included in the current response. Use this value as the next_token argument in a subsequent call of the command to get the next part of the output. | 

#### Command example
```!aws-org-resource-tag-list resource_id=ou-ab12-abcd1234```
#### Context Example
```json
{
    "AWS": {
        "Organizations": {
            "Tag": [
                {
                    "Key": "test",
                    "ResourceId": "ou-ab12-abcd1234",
                    "Value": "true"
                },
                {
                    "Key": "new",
                    "ResourceId": "ou-ab12-abcd1234",
                    "Value": "true"
                },
                {
                    "Key": "key",
                    "ResourceId": "ou-ab12-abcd1234",
                    "Value": "value"
                }
            ],
            "TagNextToken": null
        }
    }
}
```

#### Human Readable Output

>### AWS Organization *ou-ab12-abcd1234* Tags
>|Key|Value|
>|---|---|
>| test | true |
>| new | true |
>| key | value |

### aws-org-account-create

***
Creates an AWS Account that is automatically a member of the organization.

#### Base Command

`aws-org-account-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_name | The friendly name of the member account. | Required | 
| email | The email address of the owner to assign to the new member account. This email address must not already be associated with another Amazon Web Services account. Use a valid email address to complete account creation. | Required | 
| iam_user_access_to_billing | If set to ALLOW, the new account enables IAM users to access account billing information if they have the required permissions. If set to DENY, only the root user of the new account can access account billing information. Possible values are: Allow, Deny. Default is Allow. | Optional | 
| role_name | The name of an IAM role that AWS Organizations automatically pre-configures in the new member account. This role trusts the management account, allowing users in the management account to assume the role, as permitted by the management account administrator. The role has administrator permissions in the new member account. Default is OrganizationAccountAccessRole. | Optional | 
| tags | A comma-separated list of tags to attach to the newly created account. Each tag should be in the format: "key=value". | Optional | 
| request_id | The ID of the create request that is used for polling. | Optional | 
| interval_in_seconds | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 600. | Optional | 
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

#### Command example
```!aws-org-account-create account_name="New" email="user@xsoar.com" tags="new=true,test=yes" iam_user_access_to_billing=Deny```
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
                "Name": "New",
                "Status": "ACTIVE"
            }
        }
    }
}
```

#### Human Readable Output

>Creating account:

>### AWS Organization Accounts
>|Id|Arn|Name|Email|JoinedMethod|JoinedTimestamp|Status|
>|---|---|---|---|---|---|---|
>| 111222333444 | arn:aws:organizations::111222333444:account/o-abcde12345/111222333444 | New | user@xsoar.com | CREATED | 2023-09-04 09:17:14.299000+00:00 | ACTIVE |

### aws-org-account-move

***
Moves an account from one parent to another.

#### Base Command

`aws-org-account-move`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The unique identifier (ID) of the member account move. This value can be retrieved by running the command "aws-org-account-list". | Required | 
| destination_parent_id | The unique identifier (ID) of the root or organizational unit to move the account to.<br/>This value can be retrieved by running the command "aws-org-root-list".<br/>. | Required | 
| source_parent_id | The unique identifier (ID) of the root or organizational unit to move the account from.<br/>This value can be retrieved by running the command "aws-org-parent-list" with the child_id set to the account_id.<br/>. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-org-account-move source_parent_id=r-12ab account_id=111222333444 destination_parent_id=ou-ab12-abcd1234```

#### Human Readable Output

>AWS account *111222333444* moved successfully.

### aws-org-account-remove

***
Removes an account from the organization.
For more information on this action: https://docs.aws.amazon.com/organizations/latest/APIReference/API_RemoveAccountFromOrganization.html

#### Base Command

`aws-org-account-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The unique identifier (ID) of the member account to be removed from the organization. This can be obtained with the command "aws-organizations-account-list". | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example
```!aws-org-account-remove account_id=111222333444```

#### Human Readable Output

>AWS account *111222333444* removed successfully.

### aws-org-account-close

***
Closes an AWS member account within an organization.

#### Base Command

`aws-org-account-close`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The unique identifier (ID) of the member account to close. This can be obtained with the command "aws-organizations-account-list". | Required | 
| interval_in_seconds | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 600. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-org-account-close account_id=111222333444```

#### Human Readable Output

>Closing account:

>AWS account *111222333444* closed successfully.