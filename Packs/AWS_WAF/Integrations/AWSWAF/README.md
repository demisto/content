Amazon Web Services Web Application Firewall (WAF)

## Configure AWS-WAF in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Role Arn |  | False |
| Role Session Name |  | False |
| AWS Default Region |  | True |
| Role Session Duration |  | False |
| Access Key |  | False |
| Secret Key |  | False |
| Timeout | The time in seconds until a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-waf-ip-set-create

***
Create a new IP set.

#### Base Command

`aws-waf-ip-set-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The IP set name. | Required | 
| scope | The IP set scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| addresses | A comma-separated list of the IP set addresses in CIDR notation. | Optional | 
| description | The IP set description. | Optional | 
| ip_version | The IP set versions. Possible values are: IPV4, IPV6. | Required | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| tag_key | A comma-separated list of the keys of the tags to associate with the IP set. | Optional | 
| tag_value | A comma-separated list of the values of the tags to associate with the IP set. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.IpSet.Id | String | The IP set ID. | 
| AWS.Waf.IpSet.Name | String | The IP set name. | 
| AWS.Waf.IpSet.Description | String | The IP set description. | 
| AWS.Waf.IpSet.LockToken | String | The IP set lock token. | 
| AWS.Waf.IpSet.ARN | String | The IP set Amazon Resource Name. | 

#### Command example
```!aws-waf-ip-set-create ip_version=IPV4 name=name addresses="1.1.1.1/32"```
#### Context Example
```json
{
    "AWS": {
        "Waf": {
            "IpSet": {
                "ARN": "arn",
                "Description": "",
                "Id": "id",
                "LockToken": "lockToken",
                "Name": "name"
            }
        }
    }
}
```

#### Human Readable Output

>AWS Waf ip set with id id was created successfully

### aws-waf-ip-set-get

***
Get a specific IP set.

#### Base Command

`aws-waf-ip-set-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The IP set name. | Required | 
| scope | The IP set scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| id | The IP set ID. | Required | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.IpSet.Id | String | The IP set ID. | 
| AWS.Waf.IpSet.Name | String | The IP set name. | 
| AWS.Waf.IpSet.Description | String | The IP set description. | 
| AWS.Waf.IpSet.IPAddressVersion | String | The IP set IP version. | 
| AWS.Waf.IpSet.Addresses | String | The IP set IP addresses. | 
| AWS.Waf.IpSet.ARN | String | The IP set Amazon Resource Name. | 

#### Command example
```!aws-waf-ip-set-get id=id name=name```
#### Context Example
```json
{
    "AWS": {
        "Waf": {
            "IpSet": {
                "ARN": "arn",
                "Addresses": [
                    "1.1.2.2/32"
                ],
                "Description": "",
                "IPAddressVersion": "IPV4",
                "Id": "id",
                "Name": "name"
            }
        }
    }
}
```

#### Human Readable Output

>### IP Set
>|ARN|Addresses|Description|IPAddressVersion| Id  | Name |
>|---|---|---|-----|------|---|
>| arn | 1.1.2.2/32 |  | IPV4 | id  | name |


### aws-waf-ip-set-update

***
Update an IP set.

#### Base Command

`aws-waf-ip-set-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The IP set name. | Required | 
| scope | The IP set scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| id | The IP set ID. | Required | 
| addresses | A comma-separated list of the IP set addresses in CIDR notation. | Required | 
| description | The IP set description. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| is_overwrite | Whether to overwrite the existing addresses. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-ip-set-list

***
Lists IP sets.

#### Base Command

`aws-waf-ip-set-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The IP set scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| next_token | The token for the next page. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.IpSet.Id | String | The IP set ID. | 
| AWS.Waf.IpSet.Name | String | The IP set name. | 
| AWS.Waf.IpSet.Description | String | The IP set description. | 
| AWS.Waf.IpSet.LockToken | String | The IP set lock token. | 
| AWS.Waf.IpSet.ARN | unknown | The IP set Amazon Resource Name. | 
| AWS.Waf.IpSetNextToken | String | The token for the next page. | 

#### Command example
```!aws-waf-ip-set-list```
#### Context Example
```json
{
    "AWS": {
        "Waf": {
            "IpSet": [
                {
                    "ARN": "arn",
                    "Description": "",
                    "Id": "id",
                    "LockToken": "lockToken",
                    "Name": "name"
                },
                {
                    "ARN": "arn",
                    "Description": "",
                    "Id": "id1",
                    "LockToken": "lockToken1",
                    "Name": "name1"
                }
            ],
            "IpSetNextToken": "sdf"
        }
    }
}
```

#### Human Readable Output

>### List IP Sets
>|Name|Id|ARN|Description|
>|---|---|---|---|
>| name | id| arn |  |
>| name1 | id1 | arn |  |


### aws-waf-ip-set-delete

***
Delete a specific IP set.

#### Base Command

`aws-waf-ip-set-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The IP set name. | Required | 
| scope | The IP set scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| id | The IP set ID. | Required | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-regex-set-create

***
Create a new regex set.

#### Base Command

`aws-waf-regex-set-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The regex set name. | Required | 
| scope | The regex set scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| regex_pattern | A comma-separated list of the regex patterns. | Required | 
| description | The regex set description. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| tag_key | A comma-separated list of the keys of the tags to associate with the regex set. | Optional | 
| tag_value | A comma-separated list of the values of the tags to associate with the regex set. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.RegexSet.Id | String | The regex set ID. | 
| AWS.Waf.RegexSet.Name | String | The regex set name. | 
| AWS.Waf.RegexSet.Description | String | The regex set description. | 
| AWS.Waf.RegexSet.LockToken | String | The regex set lock token. | 
| AWS.Waf.RegexSet.ARN | String | The regex set Amazon Resource Name. | 

#### Command example
```!aws-waf-regex-set-create name=name regex_pattern="pattern"```
#### Context Example
```json
{
    "AWS": {
        "Waf": {
            "RegexSet": {
                "ARN": "arn",
                "Description": "",
                "Id": "id",
                "LockToken": "lockToken",
                "Name": "name"
            }
        }
    }
}
```

#### Human Readable Output

>AWS Waf regex set with id id was created successfully

### aws-waf-regex-set-get

***
Get a specific regex set.

#### Base Command

`aws-waf-regex-set-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The regex set name. | Required | 
| scope | The regex set scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| id | The regex set ID. | Required | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.RegexSet.Id | String | The regex set ID. | 
| AWS.Waf.RegexSet.Name | String | The regex set name. | 
| AWS.Waf.RegexSet.Description | String | The regex set description. | 
| AWS.Waf.RegexSet.RegularExpressionList | String | The regex set patterns list. | 
| AWS.Waf.RegexSet.ARN | String | The regex set Amazon Resource Name. | 

#### Command example
```!aws-waf-regex-set-get id=id name=name```
#### Context Example
```json
{
    "AWS": {
        "Waf": {
            "RegexSet": {
                "ARN": "arn",
                "Description": "",
                "Id": "id",
                "Name": "name",
                "RegularExpressionList": [
                    {
                        "RegexString": "^dog"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Regex Set
>|ARN|Description| Id  |Name|RegularExpressionList|
>|---|-----|---|---|---|
>| arn |  | id  | name | {'RegexString': '^dog'} |


### aws-waf-regex-set-update

***
Update a regex set.

#### Base Command

`aws-waf-regex-set-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The regex set name. | Required | 
| scope | The regex set scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| id | The regex set ID. | Required | 
| regex_pattern | A comma-separated list of the regex patterns. | Required | 
| description | The regex set description. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| is_overwrite | Whether to overwrite the existing regex patterns. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-regex-set-list

***
Lists regex sets.

#### Base Command

`aws-waf-regex-set-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The regex set scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| next_token | The token for the next page. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.RegexSet.Id | String | The regex set ID. | 
| AWS.Waf.RegexSet.Name | String | The regex set name. | 
| AWS.Waf.RegexSet.Description | String | The regex set description. | 
| AWS.Waf.RegexSet.LockToken | String | The regex set lock token. | 
| AWS.Waf.RegexSet.RegexPatternSets.ARN | unknown | The regex set Amazon Resource Name. | 
| AWS.Waf.RegexSetNextToken | String | The token for the next page. | 

#### Command example
```!aws-waf-regex-set-list```
#### Context Example
```json
{
    "AWS": {
        "Waf": {
            "RegexSet": [
                {
                    "ARN": "arn",
                    "Description": "",
                    "Id": "id",
                    "LockToken": "lockToken",
                    "Name": "name"
                },
                {
                    "ARN": "arn",
                    "Description": "",
                    "Id": "id1",
                    "LockToken": "lockToken1",
                    "Name": "name1"
                }
            ],
            "RegexSetNextToken": "name"
        }
    }
}
```

#### Human Readable Output

>### List regex Sets
>|Name|Id|ARN|Description|
>|---|---|---|---|
>| name | id | arn |  |
>| name1 | id1 | arn |  |


### aws-waf-regex-set-delete

***
Delete a specific regex set.

#### Base Command

`aws-waf-regex-set-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The regex set name. | Required | 
| scope | The regex set scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| id | The regex set ID. | Required | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-rule-group-list

***
Lists rule groups.

#### Base Command

`aws-waf-rule-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The rule group scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| next_token | The token for the next page. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.RuleGroup.Id | String | The rule group ID. | 
| AWS.Waf.RuleGroup.Name | String | The rule group name. | 
| AWS.Waf.RuleGroup.Description | String | The rule group description. | 
| AWS.Waf.RuleGroup.LockToken | String | The rule group lock token. | 
| AWS.Waf.RuleGroup.ARN | unknown | The rule group Amazon Resource Name. | 
| AWS.Waf.RuleGroupNextToken | String | The token for the next page. | 

#### Command example
```!aws-waf-rule-group-list```
#### Context Example
```json
{
    "AWS": {
        "Waf": {
            "RuleGroup": [
                {
                    "ARN": "arn",
                    "Description": "",
                    "Id": "id",
                    "LockToken": "lockToken",
                    "Name": "name"
                },
                {
                    "ARN": "arn",
                    "Description": "",
                    "Id": "id1",
                    "LockToken": "lockToken1",
                    "Name": "name1"
                }
            ],
            "RuleGroupNextToken": "name"
        }
    }
}
```

#### Human Readable Output

>### List rule groups
>|Name|Id|ARN|Description|
>|---|---|---|---|
>| name | id | arn |  |
>| name1 | id1 | arn |  |


### aws-waf-rule-group-get

***
Get a specific rule group.

#### Base Command

`aws-waf-rule-group-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The rule group name. | Required | 
| scope | The rule group scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| id | The rule group ID. | Required | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.RuleGroup.Id | String | The rule group ID. | 
| AWS.Waf.RuleGroup.Name | String | The rule group name. | 
| AWS.Waf.RuleGroup.Description | String | The rule group description. | 
| AWS.Waf.RuleGroup.Rules | String | The rule group rules. | 
| AWS.Waf.RuleGroup.ARN | String | The rule group Amazon Resource Name. | 

#### Command example
```!aws-waf-rule-group-get id=id name=name```
#### Context Example
```json
{
    "AWS": {
        "Waf": {
            "RuleGroup": {
                "ARN": "arn",
                "Capacity": 1500,
                "Description": "",
                "Id": "id",
                "LabelNamespace": "LabelNamespace",
                "Name": "name",
                "Rules": [
                    {
                        "Action": {
                            "Allow": {}
                        },
                        "Name": "name",
                        "Priority": 1,
                        "Statement": {
                            "AndStatement": {
                                "Statements": [
                                    {
                                        "ByteMatchStatement": {
                                            "FieldToMatch": {
                                                "Body": {
                                                    "OversizeHandling": "CONTINUE"
                                                }
                                            },
                                            "PositionalConstraint": "CONTAINS_WORD",
                                            "SearchString": "ssss",
                                            "TextTransformations": [
                                                {
                                                    "Priority": 0,
                                                    "Type": "BASE64_DECODE_EXT"
                                                }
                                            ]
                                        }
                                    },
                                    {
                                        "ByteMatchStatement": {
                                            "FieldToMatch": {
                                                "Body": {
                                                    "OversizeHandling": "CONTINUE"
                                                }
                                            },
                                            "PositionalConstraint": "CONTAINS_WORD",
                                            "SearchString": "fyfyu",
                                            "TextTransformations": [
                                                {
                                                    "Priority": 0,
                                                    "Type": "BASE64_DECODE_EXT"
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        },
                        "VisibilityConfig": {
                            "CloudWatchMetricsEnabled": true,
                            "MetricName": "Hey_Test",
                            "SampledRequestsEnabled": true
                        }
                    },
                    {
                        "Action": {
                            "Allow": {}
                        },
                        "Name": "name1",
                        "Priority": 2,
                        "Statement": {
                            "AndStatement": {
                                "Statements": [
                                    {
                                        "IPSetReferenceStatement": {
                                            "ARN": "arn"
                                        }
                                    },
                                    {
                                        "IPSetReferenceStatement": {
                                            "ARN": "arn"
                                        }
                                    },
                                    {
                                        "IPSetReferenceStatement": {
                                            "ARN": "arn"
                                        }
                                    }
                                ]
                            }
                        },
                        "VisibilityConfig": {
                            "CloudWatchMetricsEnabled": true,
                            "MetricName": "name",
                            "SampledRequestsEnabled": true
                        }
                    },
                    {
                        "Action": {
                            "Allow": {}
                        },
                        "Name": "Name1",
                        "Priority": 3,
                        "Statement": {
                            "ByteMatchStatement": {
                                "FieldToMatch": {
                                    "UriPath": {}
                                },
                                "PositionalConstraint": "CONTAINS",
                                "SearchString": "sdf",
                                "TextTransformations": [
                                    {
                                        "Priority": 0,
                                        "Type": "NONE"
                                    }
                                ]
                            }
                        },
                        "VisibilityConfig": {
                            "CloudWatchMetricsEnabled": true,
                            "MetricName": "Name1",
                            "SampledRequestsEnabled": true
                        }
                    },
                    {
                        "Action": {
                            "Allow": {}
                        },
                        "Name": "Name11",
                        "Priority": 4,
                        "Statement": {
                            "RegexPatternSetReferenceStatement": {
                                "ARN": "arn",
                                "FieldToMatch": {
                                    "UriPath": {}
                                },
                                "TextTransformations": [
                                    {
                                        "Priority": 0,
                                        "Type": "NONE"
                                    }
                                ]
                            }
                        },
                        "VisibilityConfig": {
                            "CloudWatchMetricsEnabled": true,
                            "MetricName": "name",
                            "SampledRequestsEnabled": true
                        }
                    }
                ],
                "VisibilityConfig": {
                    "CloudWatchMetricsEnabled": true,
                    "MetricName": "name",
                    "SampledRequestsEnabled": true
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Rule group
>|Id|Name|Description|
>|---|---|---|
>| Id | name |  |


### aws-waf-rule-group-delete

***
Delete a specific rule group.

#### Base Command

`aws-waf-rule-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The rule group name. | Required | 
| scope | The rule group scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| id | The rule group ID. | Required | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-rule-group-create

***
Create a new rule group.

#### Base Command

`aws-waf-rule-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The rule group name. | Required | 
| scope | The rule group scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| capacity | The rule group capacity. | Required | 
| description | The rule group description. | Optional | 
| cloud_watch_metrics_enabled | Whether the associated resource sends metrics to Amazon CloudWatch. Possible values are: true, false. Default is true. | Optional | 
| metric_name | The name of the Amazon CloudWatch metric dimension. The name can contain only the alphanumeric characters, hyphen, and underscore. The name can be from one to 128 characters long. It can't contain whitespace or metric names that are reserved for AWS WAF. The default will be the same as the group name provided in the name argument. | Optional | 
| sampled_requests_enabled | Whether to store a sampling of the web requests that match the rules. Possible values are: true, false. Default is true. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| tag_key | A comma-separated list of the keys of the tags to associate with the rule group. | Optional | 
| tag_value | A comma-separated list of the values of the tags to associate with the rule group. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.RuleGroup.Id | String | The rule group ID. | 
| AWS.Waf.RuleGroup.Name | String | The rule group name. | 
| AWS.Waf.RuleGroup.Description | String | The rule group description. | 
| AWS.Waf.RuleGroup.LockToken | String | The rule group lock token. | 
| AWS.Waf.RuleGroup.ARN | String | The rule group Amazon Resource Name. | 

#### Command example
```!aws-waf-rule-group-create capacity=1500 name=name```
#### Context Example
```json
{
    "AWS": {
        "Waf": {
            "RuleGroup": {
                "ARN": "arn",
                "Description": "",
                "Id": "id",
                "LockToken": "lockToken",
                "Name": "name"
            }
        }
    }
}
```

#### Human Readable Output

>AWS Waf rule group with id id was created successfully

### aws-waf-ip-rule-create

***
Create an IP rule.

#### Base Command

`aws-waf-ip-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The rule group ID to associate the rule to. | Required | 
| group_name | The rule group name to associate the rule to. | Required | 
| rule_name | The rule name. | Required | 
| scope | The rule scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| priority | The rule priority. | Required | 
| action | The rule action. Possible values are: Allow, Block, Count, Captcha, Challenge. | Required | 
| ip_set_arn | A comma-separated list of the IP set ARN. You can get those values by running the aws-waf-ip-set-list command. | Required | 
| condition_operator | The rule condition operator. If more than one value to the ip_set_arn argument is provided, a value must be provided. Possible values are: And, Or, Not. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-country-rule-create

***
Create a country rule.

#### Base Command

`aws-waf-country-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The rule group ID to associate the rule to. | Required | 
| group_name | The rule group name to associate the rule to. | Required | 
| rule_name | The rule name. | Required | 
| scope | The rule scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| priority | The rule priority. | Required | 
| action | The rule action. Possible values are: Allow, Block, Count, Captcha, Challenge. | Required | 
| country_codes | A comma-separated list of two-character country codes. | Required | 

#### Context Output

There is no context output for this command.
### aws-waf-string-match-rule-create

***
Create a string match rule.

#### Base Command

`aws-waf-string-match-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The rule group ID to associate the rule to. | Required | 
| group_name | The rule group name to associate the rule to. | Required | 
| rule_name | The rule name. | Required | 
| scope | The rule scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| priority | The rule priority. | Required | 
| action | The rule action. Possible values are: Allow, Block, Count, Captcha, Challenge. | Required | 
| match_type | The string match type. Possible values are: Exactly Matches String, Starts With String, Ends With String, Contains String, Contains Words, Matches Regex Pattern Set. | Required | 
| string_to_match | The string to match. If the match_type is Contains Words, a value must be provided. | Optional | 
| regex_set_arn | The regex set ARN. You can get those values by running the aws-waf-regex-set-list command. If the match_type is Matches Regex Pattern Set, a value must be provided. | Optional | 
| web_request_component | The web component to inspect. Possible values are: Headers, Cookies, Query Parameters, Uri Path, Query String, Body, HTTP Method. | Required | 
| oversize_handling | AWS WAF applies oversize handling to web request contents that are larger than AWS WAF can inspect. If the web_request_component is Headers, Cookies or Body, a value must be provided. Possible values are: CONTINUE, MATCH, NO_MATCH. | Optional | 
| text_transformation | The text transformation to perform. Possible values are: NONE, COMPRESS_WHITE_SPACE, HTML_ENTITY_DECODE, LOWERCASE, CMD_LINE, URL_DECODE, BASE64_DECODE, HEX_DECODE, MD5, REPLACE_COMMENTS, ESCAPE_SEQ_DECODE, SQL_HEX_DECODE, CSS_DECODE, JS_DECODE, NORMALIZE_PATH, NORMALIZE_PATH_WIN, REMOVE_NULLS, REPLACE_NULLS, BASE64_DECODE_EXT, URL_DECODE_UNI, UTF8_TO_UNICODE. Default is NONE. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-rule-delete

***
Delete a specific rule from a rule group.

#### Base Command

`aws-waf-rule-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The rule group ID to delete the rule from. | Required | 
| group_name | The rule group name to delete the rule from. | Required | 
| rule_name | The rule name. | Required | 
| scope | The rule scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-ip-statement-add

***
Adds an IP statement to an existing rule.

#### Base Command

`aws-waf-ip-statement-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The rule group ID to associate the statement to. | Required | 
| group_name | The rule group name to associate the statement to. | Required | 
| rule_name | The rule name to associate the statement to. | Required | 
| scope | The rule scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| ip_set_arn | The IP set ARN. You can get this value by running the aws-waf-ip-set-list command. | Required | 
| condition_operator | The rule condition operator. If the rule contains only one statement, a value must be provided. If the rule already contains multiple statements, this argument would be ignored. Possible values are: And, Or. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-country-statement-add

***
Adds a country statement to an existing rule.

#### Base Command

`aws-waf-country-statement-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The rule group ID to associate the statement to. | Required | 
| group_name | The rule group name to associate the statement to. | Required | 
| rule_name | The rule name to associate the statement to. | Required | 
| scope | The rule scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| country_codes | A comma-separated list of two-character country codes. | Required | 
| condition_operator | The rule condition operator. If the rule contains only one statement, a value must be provided. If the rule already contains multiple statements, this argument would be ignored. Possible values are: And, Or. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-string-match-statement-add

***
Adds a string match statement to an existing rule.

#### Base Command

`aws-waf-string-match-statement-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The rule group ID to associate the statement to. | Required | 
| group_name | The rule group name to associate the statement to. | Required | 
| rule_name | The rule name to associate the statement to. | Required | 
| scope | The rule scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| match_type | The string match type. Possible values are: Exactly Matches String, Starts With String, Ends With String, Contains String, Contains Words, Matches Regex Pattern Set. | Required | 
| string_to_match | The string to match. If the match_type is Contains Words, a value must be provided. | Optional | 
| regex_set_arn | The regex set ARN. You can get those values by running the aws-waf-regex-set-list command. If the match_type is Matches Regex Pattern Set, a value must be provided. | Optional | 
| web_request_component | The web component to inspect. Possible values are: Headers, Cookies, Query Parameters, Uri Path, Query String, Body, HTTP Method. | Required | 
| oversize_handling | AWS WAF applies oversize handling to web request contents that are larger than AWS WAF can inspect. If the web_request_component is Headers, Cookies or Body, a value must be provided. Possible values are: CONTINUE, MATCH, NO_MATCH. | Optional | 
| text_transformation | The text transformation to perform. Possible values are: NONE, COMPRESS_WHITE_SPACE, HTML_ENTITY_DECODE, LOWERCASE, CMD_LINE, URL_DECODE, BASE64_DECODE, HEX_DECODE, MD5, REPLACE_COMMENTS, ESCAPE_SEQ_DECODE, SQL_HEX_DECODE, CSS_DECODE, JS_DECODE, NORMALIZE_PATH, NORMALIZE_PATH_WIN, REMOVE_NULLS, REPLACE_NULLS, BASE64_DECODE_EXT, URL_DECODE_UNI, UTF8_TO_UNICODE. Default is NONE. | Optional | 
| condition_operator | The rule condition operator. If the rule contains only one statement, a value must be provided. If the rule already contains multiple statements, this argument would be ignored. Possible values are: And, Or. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-statement-json-add

***
Adds a generic statement to an existing rule.

#### Base Command

`aws-waf-statement-json-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The rule group ID to associate the statement to. | Required | 
| group_name | The rule group name to associate the statement to. | Required | 
| rule_name | The rule name to associate the statement to. | Required | 
| scope | The rule scope. Possible values are: Global, Regional. Default is Regional. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| statement_json | A generic JSON statement to add to the rule. You can get the templates by running the aws-waf-statement-json-template-get command. | Required | 
| condition_operator | The rule condition operator. If the rule contains only one statement, a value must be provided. If the rule already contains multiple statements, this argument would be ignored. Possible values are: And, Or. | Optional | 

#### Context Output

There is no context output for this command.
### aws-waf-statement-json-template-get

***
Gets the statement template.

#### Base Command

`aws-waf-statement-json-template-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| statement_type | The statement type. Possible values are: Ip Set, Country, String Match, Regex Pattern. | Required | 
| web_request_component | The web component to inspect. Possible values are: Headers, Cookies, Query Parameters, Uri Path, Query String, Body, HTTP Method. | Optional | 

#### Context Output

There is no context output for this command.