Amazon Web Services Web Application Firewall (WAF).
This integration was integrated and tested with version xx of AWS-WAF.

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
| AWS STS Regional Endpoints | Sets the AWS_STS_REGIONAL_ENDPOINTS environment variable to specify the AWS STS endpoint resolution logic. By default, this option is set to “legacy” in AWS. Leave empty if the environment variable is already set using server configuration. | False |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.IpSet.Id | String | The IP set ID. |
| AWS.Waf.IpSet.Name | String | The IP set name. |
| AWS.Waf.IpSet.Description | String | The IP set description. |
| AWS.Waf.IpSet.IPAddressVersion | String | The IP set IP version. |
| AWS.Waf.IpSet.Addresses | String | The IP set IP addresses. |
| AWS.Waf.IpSet.ARN | String | The IP set Amazon Resource Name. |

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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.IpSet.Id | String | The IP set ID. |
| AWS.Waf.IpSet.Name | String | The IP set name. |
| AWS.Waf.IpSet.Description | String | The IP set description. |
| AWS.Waf.IpSet.LockToken | String | The IP set lock token. |
| AWS.Waf.IpSet.ARN | unknown | The IP set Amazon Resource Name. |
| AWS.Waf.IpSetNextToken | String | The token for the next page. |

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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.RegexSet.Id | String | The regex set ID. |
| AWS.Waf.RegexSet.Name | String | The regex set name. |
| AWS.Waf.RegexSet.Description | String | The regex set description. |
| AWS.Waf.RegexSet.RegularExpressionList | String | The regex set patterns list. |
| AWS.Waf.RegexSet.ARN | String | The regex set Amazon Resource Name. |

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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.RegexSet.Id | String | The regex set ID. |
| AWS.Waf.RegexSet.Name | String | The regex set name. |
| AWS.Waf.RegexSet.Description | String | The regex set description. |
| AWS.Waf.RegexSet.LockToken | String | The regex set lock token. |
| AWS.Waf.RegexSet.RegexPatternSets.ARN | unknown | The regex set Amazon Resource Name. |
| AWS.Waf.RegexSetNextToken | String | The token for the next page. |

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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.RuleGroup.Id | String | The rule group ID. |
| AWS.Waf.RuleGroup.Name | String | The rule group name. |
| AWS.Waf.RuleGroup.Description | String | The rule group description. |
| AWS.Waf.RuleGroup.LockToken | String | The rule group lock token. |
| AWS.Waf.RuleGroup.ARN | unknown | The rule group Amazon Resource Name. |
| AWS.Waf.RuleGroupNextToken | String | The token for the next page. |

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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.RuleGroup.Id | String | The rule group ID. |
| AWS.Waf.RuleGroup.Name | String | The rule group name. |
| AWS.Waf.RuleGroup.Description | String | The rule group description. |
| AWS.Waf.RuleGroup.Rules | String | The rule group rules. |
| AWS.Waf.RuleGroup.ARN | String | The rule group Amazon Resource Name. |

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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |
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

### aws-waf-web-acl-list

***
Lists web ACLs.

#### Base Command

`aws-waf-web-acl-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The web ACL scope. Possible values are: Global, Regional. Default is Regional. | Optional |
| next_token | The token for the next page. | Optional |
| limit | The maximum number of results to return. Default is 50. | Optional |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.WebACL.Id | String | The web ACL ID. |
| AWS.Waf.WebACL.Name | String | The web ACL name. |
| AWS.Waf.WebACL.Description | String | The web ACL description. |
| AWS.Waf.WebACL.LockToken | String | The web ACL lock token. |
| AWS.Waf.WebACL.ARN | String | The web ACL Amazon Resource Name. |
| AWS.Waf.WebACLNextToken | String | The token for the next page. |

#### Command example

```!aws-waf-web-acl-list scope=Regional limit=2```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "WebACL": [
                {
                    "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
                    "Name": "prod-web-acl",
                    "Description": "Production Web ACL",
                    "LockToken": "e1b2c3d4-a1b2-c3d4-e5f6-EXAMPLE22222",
                    "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Web ACLs
>
>|Id|Name|Description|LockToken|ARN|
>|---|---|---|---|---|
>| a1b2c3d4-5678-90ab-cdef-EXAMPLE11111 | prod-web-acl | Production Web ACL | e1b2c3d4-a1b2-c3d4-e5f6-EXAMPLE22222 | arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111 |

### aws-waf-web-acl-get

***
Get a specific web ACL.

#### Base Command

`aws-waf-web-acl-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The web ACL name. | Required |
| scope | The web ACL scope. Possible values are: Global, Regional. Default is Regional. | Optional |
| id | The web ACL ID. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.WebACL.Id | String | The web ACL ID. |
| AWS.Waf.WebACL.Name | String | The web ACL name. |
| AWS.Waf.WebACL.Description | String | The web ACL description. |
| AWS.Waf.WebACL.DefaultAction | Unknown | The web ACL default action. |
| AWS.Waf.WebACL.Rules | Unknown | The web ACL rules. |
| AWS.Waf.WebACL.Capacity | Number | The web ACL capacity. |
| AWS.Waf.WebACL.ARN | String | The web ACL Amazon Resource Name. |
| AWS.Waf.WebACL.VisibilityConfig | Unknown | The web ACL visibility config. |

#### Command example

```!aws-waf-web-acl-get name=prod-web-acl id=a1b2c3d4-5678-90ab-cdef-EXAMPLE11111 scope=Regional```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "WebACL": {
                "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
                "Name": "prod-web-acl",
                "Description": "Production Web ACL",
                "DefaultAction": {"Allow": {}},
                "Rules": [],
                "Capacity": 100,
                "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
                "VisibilityConfig": {
                    "SampledRequestsEnabled": true,
                    "CloudWatchMetricsEnabled": true,
                    "MetricName": "prod-web-acl"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Web ACL
>
>|Id|Name|Description|Capacity|DefaultAction|
>|---|---|---|---|---|
>| a1b2c3d4-5678-90ab-cdef-EXAMPLE11111 | prod-web-acl | Production Web ACL | 100 | Allow: {} |

### aws-waf-web-acl-create

***
Create a new web ACL.

#### Base Command

`aws-waf-web-acl-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The web ACL name. | Required |
| scope | The web ACL scope. Possible values are: Global, Regional. Default is Regional. | Optional |
| default_action | The default action for the web ACL. Possible values are: Allow, Block. | Required |
| description | The web ACL description. | Optional |
| cloud_watch_metrics_enabled | Whether the associated resource sends metrics to Amazon CloudWatch. Possible values are: true, false. Default is true. | Optional |
| metric_name | The name of the Amazon CloudWatch metric dimension. Defaults to the web ACL name. | Optional |
| sampled_requests_enabled | Whether to store a sampling of the web requests that match the rules. Possible values are: true, false. Default is true. | Optional |
| rules_json | A JSON string representing the rules array for the web ACL. | Optional |
| tag_key | A comma-separated list of the keys of the tags to associate with the web ACL. | Optional |
| tag_value | A comma-separated list of the values of the tags to associate with the web ACL. | Optional |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.WebACL.Id | String | The web ACL ID. |
| AWS.Waf.WebACL.Name | String | The web ACL name. |
| AWS.Waf.WebACL.Description | String | The web ACL description. |
| AWS.Waf.WebACL.LockToken | String | The web ACL lock token. |
| AWS.Waf.WebACL.ARN | String | The web ACL Amazon Resource Name. |

#### Command example

```!aws-waf-web-acl-create name=test-web-acl default_action=Allow scope=Regional```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "WebACL": {
                "Id": "b2c3d4e5-6789-01ab-cdef-EXAMPLE33333",
                "Name": "test-web-acl",
                "Description": "",
                "LockToken": "f1a2b3c4-d5e6-f7a8-b9c0-EXAMPLE44444",
                "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test-web-acl/b2c3d4e5-6789-01ab-cdef-EXAMPLE33333"
            }
        }
    }
}
```

#### Human Readable Output

>### Web ACL Created
>
>|Id|Name|Description|LockToken|ARN|
>|---|---|---|---|---|
>| b2c3d4e5-6789-01ab-cdef-EXAMPLE33333 | test-web-acl |  | f1a2b3c4-d5e6-f7a8-b9c0-EXAMPLE44444 | arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test-web-acl/b2c3d4e5-6789-01ab-cdef-EXAMPLE33333 |

### aws-waf-web-acl-update

***
Update a web ACL.

#### Base Command

`aws-waf-web-acl-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The web ACL name. | Required |
| scope | The web ACL scope. Possible values are: Global, Regional. Default is Regional. | Optional |
| id | The web ACL ID. | Required |
| default_action | The default action for the web ACL. Possible values are: Allow, Block. | Optional |
| rules_json | A JSON string representing the rules array for the web ACL. Replaces existing rules. | Optional |
| description | The web ACL description. | Optional |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!aws-waf-web-acl-update name=test-web-acl id=b2c3d4e5-6789-01ab-cdef-EXAMPLE33333 scope=Regional default_action=Block```

#### Human Readable Output

>AWS Waf web ACL with id b2c3d4e5-6789-01ab-cdef-EXAMPLE33333 was updated successfully.

### aws-waf-web-acl-delete

***
Delete a specific web ACL.

#### Base Command

`aws-waf-web-acl-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The web ACL name. | Required |
| scope | The web ACL scope. Possible values are: Global, Regional. Default is Regional. | Optional |
| id | The web ACL ID. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!aws-waf-web-acl-delete name=test-web-acl id=b2c3d4e5-6789-01ab-cdef-EXAMPLE33333 scope=Regional```

#### Human Readable Output

>AWS Waf web ACL with id b2c3d4e5-6789-01ab-cdef-EXAMPLE33333 was deleted successfully

### aws-waf-web-acl-associate

***
Associate a web ACL with a resource.

#### Base Command

`aws-waf-web-acl-associate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| web_acl_arn | The ARN of the web ACL to associate with the resource. | Required |
| resource_arn | The ARN of the resource to associate with the web ACL. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!aws-waf-web-acl-associate web_acl_arn=arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 resource_arn=arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890```

#### Human Readable Output

>AWS Waf web ACL was associated with resource arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890 successfully.

### aws-waf-web-acl-disassociate

***
Disassociate a resource from its web ACL.

#### Base Command

`aws-waf-web-acl-disassociate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_arn | The ARN of the resource to disassociate from the web ACL. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!aws-waf-web-acl-disassociate resource_arn=arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890```

#### Human Readable Output

>AWS Waf web ACL was disassociated from resource arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890 successfully.

### aws-waf-web-acl-resource-list

***
Lists resources associated with a web ACL.

#### Base Command

`aws-waf-web-acl-resource-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| web_acl_arn | The ARN of the web ACL. | Required |
| resource_type | The resource type to filter by. Possible values are: APPLICATION_LOAD_BALANCER, API_GATEWAY, APPSYNC, COGNITO_USER_POOL, APP_RUNNER_SERVICE, VERIFIED_ACCESS_INSTANCE. Default is APPLICATION_LOAD_BALANCER. | Optional |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.WebACL.ResourceArns | Unknown | The ARNs of resources associated with the web ACL. |

#### Command example

```!aws-waf-web-acl-resource-list web_acl_arn=arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 resource_type=APPLICATION_LOAD_BALANCER```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "WebACL": {
                "ResourceArns": [
                    "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Resources for Web ACL
>
>|ARN|
>|---|
>| arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890 |

### aws-waf-web-acl-for-resource-get

***
Get the web ACL associated with a resource.

#### Base Command

`aws-waf-web-acl-for-resource-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_arn | The ARN of the resource whose web ACL you want to retrieve. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.WebACL.Id | String | The web ACL ID. |
| AWS.Waf.WebACL.Name | String | The web ACL name. |
| AWS.Waf.WebACL.Description | String | The web ACL description. |
| AWS.Waf.WebACL.DefaultAction | Unknown | The web ACL default action. |
| AWS.Waf.WebACL.Rules | Unknown | The web ACL rules. |
| AWS.Waf.WebACL.ARN | String | The web ACL Amazon Resource Name. |

#### Command example

```!aws-waf-web-acl-for-resource-get resource_arn=arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "WebACL": {
                "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
                "Name": "prod-web-acl",
                "Description": "Production Web ACL",
                "Capacity": 100,
                "DefaultAction": {"Allow": {}},
                "Rules": [],
                "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
            }
        }
    }
}
```

#### Human Readable Output

>### Web ACL for Resource
>
>|Id|Name|Description|Capacity|
>|---|---|---|---|
>| a1b2c3d4-5678-90ab-cdef-EXAMPLE11111 | prod-web-acl | Production Web ACL | 100 |

### aws-waf-logging-configuration-put

***
Put a logging configuration for a web ACL.

#### Base Command

`aws-waf-logging-configuration-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_arn | The ARN of the web ACL to configure logging for. | Required |
| log_destination | A comma-separated list of log destination ARNs (e.g., Kinesis Firehose delivery stream ARNs). | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.LoggingConfiguration.ResourceArn | String | The ARN of the web ACL. |
| AWS.Waf.LoggingConfiguration.LogDestinationConfigs | Unknown | The logging destination configuration. |

#### Command example

```!aws-waf-logging-configuration-put resource_arn=arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 log_destination=arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-stream```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "LoggingConfiguration": {
                "ResourceArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4",
                "LogDestinationConfigs": [
                    "arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-stream"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Logging Configuration
>
>|ResourceArn|LogDestinationConfigs|
>|---|---|
>| arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 | arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-stream |

### aws-waf-logging-configuration-get

***
Get the logging configuration for a web ACL.

#### Base Command

`aws-waf-logging-configuration-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_arn | The ARN of the web ACL. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.LoggingConfiguration.ResourceArn | String | The ARN of the web ACL. |
| AWS.Waf.LoggingConfiguration.LogDestinationConfigs | Unknown | The logging destination configuration. |

#### Command example

```!aws-waf-logging-configuration-get resource_arn=arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "LoggingConfiguration": {
                "ResourceArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4",
                "LogDestinationConfigs": [
                    "arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-stream"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Logging Configuration
>
>|ResourceArn|LogDestinationConfigs|
>|---|---|
>| arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 | arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-stream |

### aws-waf-logging-configuration-delete

***
Delete the logging configuration for a web ACL.

#### Base Command

`aws-waf-logging-configuration-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_arn | The ARN of the web ACL. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!aws-waf-logging-configuration-delete resource_arn=arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4```

#### Human Readable Output

>AWS Waf logging configuration for arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 was deleted successfully.

### aws-waf-logging-configuration-list

***
Lists logging configurations.

#### Base Command

`aws-waf-logging-configuration-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The logging configuration scope. Possible values are: Global, Regional. Default is Regional. | Optional |
| next_token | The token for the next page. | Optional |
| limit | The maximum number of results to return. Default is 50. | Optional |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.LoggingConfiguration.ResourceArn | String | The ARN of the web ACL. |
| AWS.Waf.LoggingConfiguration.LogDestinationConfigs | Unknown | The logging destination configuration. |
| AWS.Waf.LoggingConfigurationNextToken | String | The token for the next page. |

#### Command example

```!aws-waf-logging-configuration-list scope=Regional limit=2```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "LoggingConfiguration": [
                {
                    "ResourceArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4",
                    "LogDestinationConfigs": [
                        "arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-stream"
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Logging Configurations
>
>|ResourceArn|LogDestinationConfigs|
>|---|---|
>| arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 | arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-stream |

### aws-waf-tag-resource

***
Tag a resource.

#### Base Command

`aws-waf-tag-resource`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_arn | The ARN of the resource to tag. | Required |
| tag_key | A comma-separated list of the keys of the tags to add. | Required |
| tag_value | A comma-separated list of the values of the tags to add. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!aws-waf-tag-resource resource_arn=arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 tag_key=Environment,Team tag_value=Production,Security```

#### Human Readable Output

>AWS Waf resource arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 was tagged successfully.

### aws-waf-untag-resource

***
Remove tags from a resource.

#### Base Command

`aws-waf-untag-resource`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_arn | The ARN of the resource to remove tags from. | Required |
| tag_keys | A comma-separated list of the tag keys to remove. | Required |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!aws-waf-untag-resource resource_arn=arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 tag_keys=Environment,Team```

#### Human Readable Output

>AWS Waf resource arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 was untagged successfully.

### aws-waf-tag-list

***
List tags for a resource.

#### Base Command

`aws-waf-tag-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_arn | The ARN of the resource. | Required |
| next_token | The token for the next page. | Optional |
| limit | The maximum number of results to return. Default is 50. | Optional |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.TagInfoForResource.ResourceARN | String | The ARN of the resource. |
| AWS.Waf.TagInfoForResource.TagList.Key | String | The tag key. |
| AWS.Waf.TagInfoForResource.TagList.Value | String | The tag value. |
| AWS.Waf.TagNextToken | String | The token for the next page. |

#### Command example

```!aws-waf-tag-list resource_arn=arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "TagInfoForResource": {
                "ResourceARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4",
                "TagList": [
                    {"Key": "Environment", "Value": "Production"},
                    {"Key": "Team", "Value": "Security"}
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Tags
>
>|Key|Value|
>|---|---|
>| Environment | Production |
>| Team | Security |

### aws-waf-sampled-requests-get

***
Get sampled web requests for a web ACL.

#### Base Command

`aws-waf-sampled-requests-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| web_acl_arn | The ARN of the web ACL. | Required |
| rule_metric_name | The metric name assigned to the Rule or RuleGroup. | Required |
| scope | The scope. Possible values are: Global, Regional. Default is Regional. | Optional |
| start_time | The start of the time range (ISO 8601 format, e.g., 2024-01-01T00:00:00Z). Can be a relative time like "3 hours ago". | Required |
| end_time | The end of the time range (ISO 8601 format, e.g., 2024-01-01T01:00:00Z). Can be a relative time like "now". | Required |
| max_items | The number of requests to return (1-500). Default is 100. | Optional |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.SampledRequest.Action | String | The action for the request. |
| AWS.Waf.SampledRequest.Request.ClientIP | String | The client IP address. |
| AWS.Waf.SampledRequest.Request.Country | String | The client country. |
| AWS.Waf.SampledRequest.Request.Method | String | The HTTP method. |
| AWS.Waf.SampledRequest.Request.URI | String | The request URI. |
| AWS.Waf.SampledRequest.Timestamp | Date | The request timestamp. |
| AWS.Waf.SampledRequest.Weight | Number | The request weight. |
| AWS.Waf.SampledRequestsPopulationSize | Number | The total population size. |

#### Command example

```!aws-waf-sampled-requests-get web_acl_arn=arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-web-acl/a1b2c3d4 rule_metric_name=prod-web-acl scope=Regional max_items=5 start_time="2024-01-01T00:00:00Z" end_time="2024-01-01T01:00:00Z"```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "SampledRequest": [
                {
                    "Request": {
                        "ClientIP": "203.0.113.50",
                        "Country": "US",
                        "HTTPVersion": "HTTP/2.0",
                        "Headers": [
                            {"Name": "Host", "Value": "example.com"}
                        ],
                        "Method": "GET",
                        "URI": "/index.html"
                    },
                    "Weight": 1,
                    "Timestamp": 1704067200,
                    "Action": "ALLOW"
                },
                {
                    "Request": {
                        "ClientIP": "198.51.100.25",
                        "Country": "DE",
                        "HTTPVersion": "HTTP/1.1",
                        "Headers": [
                            {"Name": "Host", "Value": "example.com"}
                        ],
                        "Method": "POST",
                        "URI": "/api/login"
                    },
                    "Weight": 1,
                    "Timestamp": 1704067260,
                    "Action": "BLOCK"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Sampled Requests (Population Size: 1250)
>
>|Action|ClientIP|Country|Method|URI|Timestamp|
>|---|---|---|---|---|---|
>| ALLOW | 203.0.113.50 | US | GET | /index.html | 1704067200 |
>| BLOCK | 198.51.100.25 | DE | POST | /api/login | 1704067260 |

### aws-waf-managed-rule-group-list

***
Lists available managed rule groups.

#### Base Command

`aws-waf-managed-rule-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The scope. Possible values are: Global, Regional. Default is Regional. | Optional |
| next_token | The token for the next page. | Optional |
| limit | The maximum number of results to return. Default is 50. | Optional |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.ManagedRuleGroup.VendorName | String | The vendor name. |
| AWS.Waf.ManagedRuleGroup.Name | String | The managed rule group name. |
| AWS.Waf.ManagedRuleGroup.Description | String | The managed rule group description. |
| AWS.Waf.ManagedRuleGroupNextToken | String | The token for the next page. |

#### Command example

```!aws-waf-managed-rule-group-list scope=Regional limit=3```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "ManagedRuleGroup": [
                {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesCommonRuleSet",
                    "Description": "Contains rules that are generally applicable to web applications."
                },
                {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesKnownBadInputsRuleSet",
                    "Description": "Contains rules to block request patterns known to be invalid and are associated with exploitation or discovery of vulnerabilities."
                },
                {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesSQLiRuleSet",
                    "Description": "Contains rules that allow you to block request patterns associated with exploitation of SQL databases."
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Available Managed Rule Groups
>
>|VendorName|Name|Description|
>|---|---|---|
>| AWS | AWSManagedRulesCommonRuleSet | Contains rules that are generally applicable to web applications. |
>| AWS | AWSManagedRulesKnownBadInputsRuleSet | Contains rules to block request patterns known to be invalid and are associated with exploitation or discovery of vulnerabilities. |
>| AWS | AWSManagedRulesSQLiRuleSet | Contains rules that allow you to block request patterns associated with exploitation of SQL databases. |

### aws-waf-managed-rule-group-describe

***
Describe a managed rule group.

#### Base Command

`aws-waf-managed-rule-group-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_name | The vendor name (e.g., AWS). | Required |
| name | The managed rule group name. | Required |
| scope | The scope. Possible values are: Global, Regional. Default is Regional. | Optional |
| version_name | The version name. If not provided, the default version is used. | Optional |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1, af-south-1, ap-east-1, ap-east-2, ap-northeast-3, ap-south-2, ap-southeast-3, ap-southeast-4, cn-north-1, cn-northwest-1, eu-central-2, eu-south-1, eu-south-2, me-south-1, me-central-1. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Waf.ManagedRuleGroup.Capacity | Number | The capacity required by the rule group. |
| AWS.Waf.ManagedRuleGroup.Rules | Unknown | The rules in the managed rule group. |
| AWS.Waf.ManagedRuleGroup.LabelNamespace | String | The label namespace. |
| AWS.Waf.ManagedRuleGroup.AvailableLabels | Unknown | The labels available for rules in the rule group. |
| AWS.Waf.ManagedRuleGroup.ConsumedLabels | Unknown | The labels consumed by rules in the rule group. |
| AWS.Waf.ManagedRuleGroup.VersionName | String | The version name. |
| AWS.Waf.ManagedRuleGroup.SnsTopicArn | String | The SNS topic ARN for notifications. |

#### Command example

```!aws-waf-managed-rule-group-describe vendor_name=AWS name=AWSManagedRulesCommonRuleSet scope=Regional```

#### Context Example

```json
{
    "AWS": {
        "Waf": {
            "ManagedRuleGroup": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesCommonRuleSet",
                "VersionName": "Version_2.0",
                "Capacity": 700,
                "LabelNamespace": "awswaf:managed:aws:core-rule-set:",
                "Rules": [
                    {"Name": "NoUserAgent_HEADER", "Action": {"Count": {}}},
                    {"Name": "UserAgent_BadBots_HEADER", "Action": {"Block": {}}},
                    {"Name": "SizeRestrictions_QUERYSTRING", "Action": {"Block": {}}}
                ],
                "AvailableLabels": [
                    {"Name": "awswaf:managed:aws:core-rule-set:NoUserAgent_Header"}
                ],
                "ConsumedLabels": [],
                "SnsTopicArn": "arn:aws:sns:us-east-1:123456789012:aws-waf-managed-rule-group-updates"
            }
        }
    }
}
```

#### Human Readable Output

>### Managed Rule Group
>
>|VendorName|Name|VersionName|Capacity|LabelNamespace|
>|---|---|---|---|---|
>| AWS | AWSManagedRulesCommonRuleSet | Version_2.0 | 700 | awswaf:managed:aws:core-rule-set: |
